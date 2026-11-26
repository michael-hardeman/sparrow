with Interfaces; use Interfaces;
with Sparrow.Http.Hpack_Tables; use Sparrow.Http.Hpack_Tables;

package body Sparrow.Http.Hpack with SPARK_Mode is

   Largest_Integer : constant := 2 ** 28;   --  far beyond any length or index a valid block holds

   ---------------------------------------------------------------------------------------------------------------
   --  the dynamic table

   --  The entry Offset places back from the newest (0: the newest).
   function Entry_At (This : Decoder; Offset : Natural) return Table_Entry is
     (This.Entries (This.Newest - Entry_Position'Mod (Offset)))
      with Pre => Offset < This.Count;

   procedure Evict_Oldest (This : in out Decoder)
      with Pre => This.Count > 0, Post => This.Count = This.Count'Old - 1
   is
      Oldest : constant Table_Entry := Entry_At (This, This.Count - 1);
      Freed  : constant Natural := Oldest.Name_Length + Oldest.Value_Length + 32;
   begin
      This.Count := This.Count - 1;
      This.Size  := (if This.Count = 0 or else This.Size < Freed then 0 else This.Size - Freed);
   end Evict_Oldest;

   --  Evict until Needed more bytes fit under Max_Size, or the table is empty.
   procedure Make_Room (This : in out Decoder; Needed : Natural) with Post => This.Count <= This.Count'Old is
   begin
      while This.Count > 0 and then This.Size > This.Max_Size - Natural'Min (Needed, This.Max_Size) loop
         pragma Loop_Invariant (This.Count <= This.Count'Loop_Entry);
         pragma Loop_Variant (Decreases => This.Count);
         Evict_Oldest (This);
      end loop;
      if This.Count = 0 then
         This.Size := 0;
      end if;
   end Make_Room;

   --  RFC 7541 4.4: add Name and Value as the newest entry; an entry larger than the table empties it.
   procedure Insert (This : in out Decoder; Name, Value : String) is
   begin
      if Name'Length > Table_Capacity or else Value'Length > Table_Capacity - Name'Length
        or else Name'Length + Value'Length + 32 > This.Max_Size
      then
         This.Count := 0;
         This.Size  := 0;
         return;
      end if;
      declare
         Needed : constant Table_Size := Name'Length + Value'Length + 32;
      begin
         Make_Room (This, Needed);
         if This.Count = Max_Entries then   --  cannot happen while sizes add up; kept so the ring never laps
            Evict_Oldest (This);
         end if;
         This.Newest := This.Newest + 1;
         This.Entries (This.Newest) :=
           (Start => This.Next_Byte, Name_Length => Name'Length, Value_Length => Value'Length);
         for Item of Name loop
            This.Bytes (This.Next_Byte) := Item;
            This.Next_Byte := This.Next_Byte + 1;
         end loop;
         for Item of Value loop
            This.Bytes (This.Next_Byte) := Item;
            This.Next_Byte := This.Next_Byte + 1;
         end loop;
         This.Count := This.Count + 1;
         This.Size  := Table_Size'Min (This.Size + Natural'Min (Needed, Table_Capacity - This.Size), Table_Capacity);
      end;
   end Insert;

   ---------------------------------------------------------------------------------------------------------------
   --  the encoder

   procedure Encode_Integer (Into : in out Buffer; Value : Natural; Prefix_Bits : Positive; Flags : Natural) is
      Limit : constant Natural := 2 ** Prefix_Bits - 1;
      Rest  : Natural;
   begin
      if Value < Limit then
         Append (Into, Character'Val ((Flags + Value) mod 256));
         return;
      end if;
      Append (Into, Character'Val ((Flags + Limit) mod 256));
      Rest := Value - Limit;
      while Rest >= 128 loop
         pragma Loop_Invariant (Valid (Into));
         pragma Loop_Variant (Decreases => Rest);
         Append (Into, Character'Val (Rest mod 128 + 128));
         Rest := Rest / 128;
      end loop;
      Append (Into, Character'Val (Rest));
   end Encode_Integer;

   procedure Encode_String (Into : in out Buffer; Text : String) with Pre => Valid (Into), Post => Valid (Into) is
   begin
      Encode_Integer (Into, Text'Length, 7, 0);   --  not Huffman-coded
      Append (Into, Text);
   end Encode_String;

   function Static_Name (Index : Static_Index) return String is
     (Static_Text (Static_Entries (Index).Name_First .. Static_Entries (Index).Name_Last))
      with Pre => Static_Entries (Index).Name_First in Static_Text'Range
                  and then Static_Entries (Index).Name_Last in Static_Text'Range;

   procedure Encode_Status (Into : in out Buffer; Status : Status_Code) is
      Index : constant Natural :=
        (case Status is
            when 200 => 8, when 204 => 9, when 206 => 10, when 304 => 11, when 400 => 12, when 404 => 13,
            when 500 => 14, when others => 0);
   begin
      if Index > 0 then
         Encode_Integer (Into, Index, 7, 128);   --  indexed field
      else
         Encode_Integer (Into, 8, 4, 0);         --  literal, not indexed, named by entry 8 (:status)
         Append (Into, Character'Val (3));
         Append (Into, Character'Val (Character'Pos ('0') + Natural (Status) / 100 mod 10));
         Append (Into, Character'Val (Character'Pos ('0') + Natural (Status) / 10 mod 10));
         Append (Into, Character'Val (Character'Pos ('0') + Natural (Status) mod 10));
      end if;
   end Encode_Status;

   procedure Encode_Field (Into : in out Buffer; Name, Value : String) is
      Index : Natural := 0;
   begin
      for Candidate in Static_Index loop
         if Static_Entries (Candidate).Name_First in Static_Text'Range
           and then Static_Entries (Candidate).Name_Last in Static_Text'Range
           and then Static_Name (Candidate) = Name
         then
            Index := Natural (Candidate);
            exit;
         end if;
      end loop;
      Encode_Integer (Into, Index, 4, 0);   --  a literal that is not indexed
      if Index = 0 then
         Encode_String (Into, Name);
      end if;
      Encode_String (Into, Value);
   end Encode_Field;

   ---------------------------------------------------------------------------------------------------------------
   --  the decoder

   procedure Decode_Huffman (Source : String; Text : in out String; Last : in out Natural; Result : out Outcome) is
      Code   : Unsigned_32 := 0;   --  the bits read since the last symbol
      Length : Natural := 0;       --  how many
   begin
      Result := Decoded;
      for Byte of Source loop
         pragma Loop_Invariant (Length < 30 and then Last in Last'Loop_Entry .. Text'Last);
         for Bit in reverse 0 .. 7 loop
            pragma Loop_Invariant
              (Length < 30 and then Last in Last'Loop_Entry .. Text'Last);
            Code   := Code * 2 + Unsigned_32 (Character'Pos (Byte) / 2 ** Bit mod 2);
            Length := Length + 1;
            if Length >= Code_Length'First
              and then Code >= Unsigned_32 (First_Code (Length))
              and then Code - Unsigned_32 (First_Code (Length)) < Unsigned_32 (Code_Count (Length))
            then
               declare
                  Position : constant Natural :=
                    First_Symbol (Length) + Natural (Code - Unsigned_32 (First_Code (Length)));
               begin
                  if Position > Symbol'Last or else By_Code (Position) = End_Of_String then
                     Result := Malformed;   --  RFC 7541 5.2: EOS inside a string is an error
                     return;
                  elsif Last = Text'Last then
                     Result := Too_Large;
                     return;
                  end if;
                  Last        := Last + 1;
                  Text (Last) := Character'Val (By_Code (Position));
                  Code        := 0;
                  Length      := 0;
               end;
            elsif Length = 30 then   --  no code is longer than 30 bits
               Result := Malformed;
               return;
            end if;
         end loop;
      end loop;
      --  Padding: fewer than 8 bits, all ones (the start of EOS).
      if Length > 7 or else Code /= Shift_Left (1, Length) - 1 then
         Result := Malformed;
      end if;
   end Decode_Huffman;

   procedure Decode
     (This      : in out Decoder;
      Block     : String;
      Text      : out String;
      Text_Last : out Natural;
      Fields    : out Field_Array;
      Count     : out Natural;
      Result    : out Outcome)
   is
      Position : Natural := Block'First;   --  the next byte of Block
      Seen     : Boolean := False;         --  a field was decoded: no more size updates

      --  RFC 7541 5.1.
      procedure Read_Integer (Prefix_Bits : Positive; Value : out Natural; Valid : out Boolean)
         with Pre  => Prefix_Bits <= 8 and then Position in Block'Range and then Block'Last < Positive'Last,
              Post => Value <= Largest_Integer and then Position in Position'Old + 1 .. Block'Last + 1
      is
         Limit : constant Natural := 2 ** Prefix_Bits - 1;
         Scale : constant array (0 .. 3) of Natural := [1, 2 ** 7, 2 ** 14, 2 ** 21];
         Step  : Natural range 0 .. 3 := 0;
         Byte  : Natural;
      begin
         Value    := Character'Pos (Block (Position)) mod (Limit + 1);
         Position := Position + 1;
         Valid    := True;
         if Value < Limit then
            return;
         end if;
         loop
            pragma Loop_Invariant
              (Value <= Largest_Integer and then Position in Position'Loop_Entry .. Block'Last + 1);
            if Position > Block'Last then
               Valid := False;
               return;
            end if;
            Byte     := Character'Pos (Block (Position));
            Position := Position + 1;
            --  Name the factors and bound them: a product of bounded constants is linear for the provers.
            declare
               Fragment : constant Natural := Byte mod 128;
               Factor   : constant Natural := Scale (Step);
            begin
               pragma Assert (Fragment <= 127 and then Factor <= 2 ** 21);
               if Fragment * Factor > Largest_Integer - Value then
                  Valid := False;
                  return;
               end if;
               Value := Value + Fragment * Factor;
            end;
            exit when Byte < 128;
            if Step = 3 then
               Valid := False;
               return;
            end if;
            Step := Step + 1;
         end loop;
      end Read_Integer;

      --  RFC 7541 5.2: a string literal, written to Text after Text_Last.
      procedure Read_String (Status : out Outcome)
         with Pre  => Position in Block'Range and then Block'Last < Positive'Last and then Text'First = 1
                      and then Text'Last < Positive'Last and then Text_Last <= Text'Last,
              Post => Text_Last in Text_Last'Old .. Text'Last and then Position in Position'Old + 1 .. Block'Last + 1
      is
         Huffman : constant Boolean := Character'Pos (Block (Position)) >= 128;
         Length  : Natural;
         Valid   : Boolean;
      begin
         Read_Integer (7, Length, Valid);
         if not Valid or else Length > Block'Last + 1 - Position then
            Status := Malformed;
            return;
         end if;
         declare
            First : constant Positive := Position;
            Last  : constant Natural := Position + Length - 1;
         begin
            Position := Position + Length;
            if Huffman then
               Decode_Huffman (Block (First .. Last), Text, Text_Last, Status);
            elsif Length > Text'Last - Text_Last then
               Status := Too_Large;
            else
               Text (Text_Last + 1 .. Text_Last + Length) := Block (First .. Last);
               Text_Last := Text_Last + Length;
               Status    := Decoded;
            end if;
         end;
      end Read_String;

      --  The name (or value) of table entry Index, written to Text after Text_Last.
      procedure Copy_Entry (Index : Positive; Value_Part : Boolean; Status : out Outcome)
         with Pre  => Text'First = 1 and then Text'Last < Positive'Last and then Text_Last <= Text'Last,
              Post => Text_Last in Text_Last'Old .. Text'Last
      is
      begin
         if Index <= Static_Size then
            declare
               Item  : constant Static_Entry := Static_Entries (Static_Index (Index));
               First : constant Natural := (if Value_Part then Item.Value_First else Item.Name_First);
               Last  : constant Natural := (if Value_Part then Item.Value_Last else Item.Name_Last);
            begin
               if Last < First then
                  Status := Decoded;
               elsif First not in Static_Text'Range or else Last not in Static_Text'Range then
                  Status := Malformed;   --  cannot happen: the table is well formed
               elsif Last - First + 1 > Text'Last - Text_Last then
                  Status := Too_Large;
               else
                  Text (Text_Last + 1 .. Text_Last + (Last - First + 1)) := Static_Text (First .. Last);
                  Text_Last := Text_Last + (Last - First + 1);
                  Status    := Decoded;
               end if;
            end;
         elsif Index - Static_Size > This.Count then
            Status := Malformed;   --  RFC 7541 2.3.3: an index past both tables
         else
            declare
               Item   : constant Table_Entry := Entry_At (This, Index - Static_Size - 1);
               Start  : constant Ring_Position :=
                 (if Value_Part then Item.Start + Ring_Position'Mod (Item.Name_Length) else Item.Start);
               Length : constant Table_Size := (if Value_Part then Item.Value_Length else Item.Name_Length);
            begin
               if Length > Text'Last - Text_Last then
                  Status := Too_Large;
                  return;
               end if;
               for Offset in 0 .. Length - 1 loop
                  pragma Loop_Invariant (Text_Last = Text_Last'Loop_Entry + Offset);
                  Text_Last := Text_Last + 1;
                  Text (Text_Last) := This.Bytes (Start + Ring_Position'Mod (Offset));
               end loop;
               Status := Decoded;
            end;
         end if;
      end Copy_Entry;

      Prefix  : Natural;
      Index   : Natural;
      Valid   : Boolean;
      Current : Field;
   begin
      Text      := [others => ' '];
      Text_Last := 0;
      Fields    := [others => (others => <>)];
      Count     := 0;
      Result    := Decoded;
      while Position in Block'Range loop
         pragma Loop_Invariant
           (Text_Last <= Text'Last and then Count <= Fields'Last
            and then (for all Item in 1 .. Count => Within (Fields (Item), Text_Last)));
         pragma Loop_Variant (Increases => Position);
         Prefix := Character'Pos (Block (Position));

         if Prefix in 32 .. 63 then   --  a dynamic table size update (6.3), only before the first field
            Read_Integer (5, Index, Valid);
            if Seen or else not Valid or else Index > Table_Capacity then
               Result := Malformed;
               return;
            end if;
            This.Max_Size := Index;
            Make_Room (This, 0);
         else
            if Count = Fields'Last then
               Result := Too_Large;
               return;
            end if;
            Seen := True;
            Read_Integer ((if Prefix >= 128 then 7 elsif Prefix >= 64 then 6 else 4), Index, Valid);
            if not Valid or else (Prefix >= 128 and then Index = 0) then
               Result := Malformed;
               return;
            end if;

            --  The name: from the tables, or a literal.
            Current.Name_First := Text_Last + 1;
            if Index > 0 then
               Copy_Entry (Index, Value_Part => False, Status => Result);
            elsif Position > Block'Last then
               Result := Malformed;
            else
               Read_String (Result);
            end if;
            if Result /= Decoded then
               return;
            end if;
            Current.Name_Last := Text_Last;

            --  The value: from the table for an indexed field, otherwise a literal.
            Current.Value_First := Text_Last + 1;
            if Prefix >= 128 then
               Copy_Entry (Index, Value_Part => True, Status => Result);
            elsif Position > Block'Last then
               Result := Malformed;
            else
               Read_String (Result);
            end if;
            if Result /= Decoded then
               return;
            end if;
            Current.Value_Last := Text_Last;

            Count := Count + 1;
            Fields (Count) := Current;
            if Prefix in 64 .. 127 then   --  incremental indexing (6.2.1)
               Insert (This, Text (Current.Name_First .. Current.Name_Last),
                       Text (Current.Value_First .. Current.Value_Last));
            end if;
         end if;
      end loop;
   end Decode;

end Sparrow.Http.Hpack;
