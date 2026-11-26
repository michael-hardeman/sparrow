package body Sparrow.Deflate with SPARK_Mode is

   Min_Match   : constant := 3;
   Max_Match   : constant := 258;
   --  Effort, chosen for serving: on text, about gzip -6's size at more than gzip -6's speed.
   Max_Chain   : constant := 8;     --  candidates tried at a position
   Nice_Length : constant := 64;    --  a match this long is taken without trying further candidates
   Lazy_Limit  : constant := 16;    --  a match this long is taken without trying the next position

   subtype Code_Length is Natural range 0 .. 15;
   type Count_Array is array (Natural range <>) of Unsigned_32;
   type Length_Array is array (Natural range <>) of Code_Length;
   type Code_Array is array (Natural range <>) of Unsigned_32;

   subtype Litlen_Symbol is Natural range 0 .. 285;
   subtype Distance_Symbol is Natural range 0 .. 29;
   subtype Length_Symbol is Natural range 0 .. 28;   --  a match length's symbol, less 257
   subtype Code_Length_Symbol is Natural range 0 .. 18;
   End_Of_Block : constant Litlen_Symbol := 256;

   ---------------------------------------------------------------------------------------------------------------
   --  the tables of RFC 1951 3.2.5

   subtype Match_Length is Natural range Min_Match .. Max_Match;
   subtype Match_Distance is Natural range 1 .. Window_Size;

   Length_Base  : constant array (Length_Symbol) of Match_Length :=
     [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
      258];
   Length_Extra : constant array (Length_Symbol) of Natural range 0 .. 5 :=
     [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];

   Distance_Base  : constant array (Distance_Symbol) of Match_Distance :=
     [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
      6145, 8193, 12289, 16385, 24577];
   Distance_Extra : constant array (Distance_Symbol) of Natural range 0 .. 13 :=
     [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

   --  The order code length code lengths are sent in (3.2.7).
   Code_Length_Order : constant array (Code_Length_Symbol) of Code_Length_Symbol :=
     [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

   type Length_Code_Table is array (Match_Length) of Length_Symbol;

   function Make_Length_Codes return Length_Code_Table is
      Result : Length_Code_Table := [others => 0];
   begin
      for Length in Match_Length loop
         for Symbol in Length_Symbol loop
            if Length_Base (Symbol) <= Length then
               Result (Length) := Symbol;
            end if;
         end loop;
      end loop;
      return Result;
   end Make_Length_Codes;

   Length_Code : constant Length_Code_Table := Make_Length_Codes;

   --  A distance's symbol: Near (D - 1) for D up to 256, Far ((D - 1) / 128) beyond (every base past 256 is one
   --  more than a multiple of 128).
   type Distance_Code_Table is array (0 .. 255) of Distance_Symbol;

   function Symbol_Of_Distance (Distance : Match_Distance) return Distance_Symbol is
      Result : Distance_Symbol := 0;
   begin
      for Symbol in Distance_Symbol loop
         if Distance_Base (Symbol) <= Distance then
            Result := Symbol;
         end if;
      end loop;
      return Result;
   end Symbol_Of_Distance;

   function Make_Near return Distance_Code_Table is
      Result : Distance_Code_Table;
   begin
      for Index in Result'Range loop
         Result (Index) := Symbol_Of_Distance (Index + 1);
      end loop;
      return Result;
   end Make_Near;

   function Make_Far return Distance_Code_Table is
      Result : Distance_Code_Table;
   begin
      for Index in Result'Range loop
         Result (Index) := Symbol_Of_Distance (Index * 128 + 1);
      end loop;
      return Result;
   end Make_Far;

   Near_Code : constant Distance_Code_Table := Make_Near;
   Far_Code  : constant Distance_Code_Table := Make_Far;

   function Distance_Code (Distance : Match_Distance) return Distance_Symbol is
     (if Distance <= 256 then Near_Code (Distance - 1) else Far_Code ((Distance - 1) / 128));

   ---------------------------------------------------------------------------------------------------------------
   --  Huffman codes

   function Reversed (Code : Unsigned_32; Width : Code_Length) return Unsigned_32 is
      Rest   : Unsigned_32 := Code;
      Result : Unsigned_32 := 0;
   begin
      for Bit in 1 .. Width loop
         Result := Shift_Left (Result, 1) or (Rest and 1);
         Rest   := Shift_Right (Rest, 1);
      end loop;
      return Result;
   end Reversed;

   --  The canonical codes of 3.2.2 for Lengths, bit-reversed: DEFLATE sends Huffman codes from their top bit,
   --  into a stream filled from each byte's bottom bit.
   procedure Make_Codes (Lengths : Length_Array; Codes : out Code_Array)
      with Pre => Codes'First = Lengths'First and then Codes'Last = Lengths'Last
   is
      Count : array (Code_Length) of Unsigned_32 := [others => 0];
      Next  : array (Code_Length) of Unsigned_32 := [others => 0];
      Code  : Unsigned_32 := 0;
   begin
      Codes := [others => 0];
      for Length of Lengths loop
         Count (Length) := Count (Length) + 1;
      end loop;
      Count (0) := 0;
      for Bits in 1 .. Code_Length'Last loop
         Code := Shift_Left (Code + Count (Bits - 1), 1);
         Next (Bits) := Code;
      end loop;
      for Symbol in Lengths'Range loop
         if Lengths (Symbol) > 0 then
            Codes (Symbol) := Reversed (Next (Lengths (Symbol)), Lengths (Symbol));
            Next (Lengths (Symbol)) := Next (Lengths (Symbol)) + 1;
         end if;
      end loop;
   end Make_Codes;

   Max_Alphabet : constant := 320;

   --  Code lengths of at most Limit bits for symbols used Frequency times: a Huffman code, then lengths past
   --  Limit brought in while keeping the code complete (as miniz does). At least two symbols get codes, used or
   --  not: decoders refuse a code of one symbol.
   procedure Build_Lengths (Frequency : Count_Array; Limit : Code_Length; Lengths : out Length_Array)
      with Pre => Frequency'First = 0 and then Frequency'Length in 2 .. Max_Alphabet
                  and then Lengths'First = 0 and then Lengths'Last = Frequency'Last and then Limit >= 7
   is
      subtype Node is Positive range 1 .. 2 * Max_Alphabet;
      Weights : array (Node) of Unsigned_64 := [others => 0];
      Parent  : array (Node) of Node := [others => 1];
      Depth   : array (Node) of Natural range 0 .. 2 * Max_Alphabet := [others => 0];
      Sorted  : array (1 .. Max_Alphabet) of Natural := [others => 0];   --  symbols, least used first
      Used    : Natural range 0 .. Max_Alphabet := 0;
      Counts  : array (Code_Length) of Unsigned_32 := [others => 0];
      Wanted  : Count_Array := Frequency;
      Extra   : Natural := 0;
   begin
      Lengths := [others => 0];
      for Symbol in Wanted'Range loop
         if Wanted (Symbol) > 0 then
            Extra := Extra + (if Extra < 2 then 1 else 0);
         end if;
      end loop;
      for Symbol in Wanted'Range loop
         exit when Extra >= 2;
         if Wanted (Symbol) = 0 then
            Wanted (Symbol) := 1;
            Extra := Extra + 1;
         end if;
      end loop;

      --  Sorted by use, then symbol: insertion sort, the alphabets being small.
      for Symbol in Wanted'Range loop
         if Wanted (Symbol) > 0 and then Used < Max_Alphabet then
            declare
               Place : Positive := Used + 1;
            begin
               while Place > 1 and then Wanted (Sorted (Place - 1)) > Wanted (Symbol) loop
                  pragma Loop_Invariant (Place in 2 .. Used + 1);
                  pragma Loop_Invariant (for all Index in 1 .. Max_Alphabet => Sorted (Index) in Wanted'Range);
                  Sorted (Place) := Sorted (Place - 1);
                  Place := Place - 1;
               end loop;
               Sorted (Place) := Symbol;
               Used := Used + 1;
            end;
         end if;
         pragma Loop_Invariant (for all Index in 1 .. Max_Alphabet => Sorted (Index) in Wanted'Range);
      end loop;
      if Used < 2 then
         return;   --  not reached: two symbols were made used above
      end if;

      --  Two queues: the leaves in order, and the inner nodes, made in order of weight.
      for Leaf in 1 .. Used loop
         Weights (Leaf) := Unsigned_64 (Wanted (Sorted (Leaf)));
      end loop;
      declare
         Leaf  : Positive := 1;
         Inner : Positive := Used + 1;
      begin
         for Made in Used + 1 .. 2 * Used - 1 loop
            pragma Loop_Invariant (Leaf in 1 .. Used + 1 and then Inner in Used + 1 .. Made);
            for Pick in 1 .. 2 loop
               pragma Loop_Invariant (Leaf in 1 .. Used + 1 and then Inner in Used + 1 .. Made);
               declare
                  Child : Node;
               begin
                  if Leaf <= Used and then (Inner >= Made or else Weights (Leaf) <= Weights (Inner)) then
                     Child := Leaf;
                     Leaf  := Leaf + 1;
                  elsif Inner < Made then
                     Child := Inner;
                     Inner := Inner + 1;
                  else
                     return;   --  not reached: two nodes wait at every step
                  end if;
                  Parent (Child) := Made;
                  Weights (Made) := Weights (Made) + Weights (Child);
               end;
            end loop;
         end loop;
      end;

      --  Depths from the root down: a parent is always made after its children.
      Depth (2 * Used - 1) := 0;
      for Item in reverse 1 .. 2 * Used - 2 loop
         Depth (Item) := Natural'Min (Depth (Parent (Item)), 2 * Max_Alphabet - 1) + 1;
      end loop;

      --  How many codes of each length, those past Limit at Limit; then lengthen shorter codes until the
      --  lengths fit (Kraft's sum back to one).
      for Leaf in 1 .. Used loop
         Counts (Natural'Min (Depth (Leaf), Limit)) := Counts (Natural'Min (Depth (Leaf), Limit)) + 1;
      end loop;
      declare
         Total : Unsigned_64 := 0;
      begin
         for Length in 1 .. Limit loop
            Total := Total + Shift_Left (Unsigned_64 (Counts (Length)), Limit - Length);
         end loop;
         for Round in 1 .. 2 * Max_Alphabet loop
            exit when Total <= Shift_Left (1, Limit) or else Counts (Limit) = 0;
            Counts (Limit) := Counts (Limit) - 1;
            for Length in reverse 1 .. Limit - 1 loop
               if Counts (Length) > 0 then
                  Counts (Length) := Counts (Length) - 1;
                  Counts (Length + 1) := Counts (Length + 1) + 2;
                  exit;
               end if;
            end loop;
            Total := Total - 1;
         end loop;
      end;

      --  The shortest codes to the most used symbols.
      declare
         Next : Natural := Used;
      begin
         for Length in 1 .. Limit loop
            pragma Loop_Invariant (Next <= Used);
            for Times in 1 .. Counts (Length) loop
               pragma Loop_Invariant (Next <= Used);
               exit when Next = 0;
               Lengths (Sorted (Next)) := Length;
               Next := Next - 1;
            end loop;
         end loop;
      end;
   end Build_Lengths;

   function Fixed_Litlen_Lengths return Length_Array is
     ([for Symbol in 0 .. 287 => (if Symbol <= 143 then 8 elsif Symbol <= 255 then 9 elsif Symbol <= 279 then 7
                                   else 8)]);

   Fixed_Litlen_Length   : constant Length_Array (0 .. 287) := Fixed_Litlen_Lengths;
   Fixed_Distance_Length : constant Length_Array (Distance_Symbol) := [others => 5];

   function Codes_Of (Lengths : Length_Array) return Code_Array
      with Post => Codes_Of'Result'First = Lengths'First and then Codes_Of'Result'Last = Lengths'Last
   is
      Result : Code_Array (Lengths'Range);
   begin
      Make_Codes (Lengths, Result);
      return Result;
   end Codes_Of;

   Fixed_Litlen_Code   : constant Code_Array (0 .. 287) := Codes_Of (Fixed_Litlen_Length);
   Fixed_Distance_Code : constant Code_Array (Distance_Symbol) := Codes_Of (Fixed_Distance_Length);

   ---------------------------------------------------------------------------------------------------------------
   --  the bit stream

   type Writer is record
      Bits  : Unsigned_64 := 0;
      Count : Natural range 0 .. 7 := 0;   --  bits waiting in Bits
      Next  : Positive := 1;               --  where the next byte goes
      Full  : Boolean := False;            --  a byte did not fit
   end record;

   procedure Put (Into : in out Writer; Output : in out String; Value : Unsigned_32; Width : Natural)
      with Pre  => Output'Last < Positive'Last and then Width <= 32
                   and then Into.Next in Output'First .. Output'Last + 1,
           Post => Into.Next in Output'First .. Output'Last + 1
                   and then Into.Count = (Into.Count'Old + Width) mod 8,
           Inline
   is
      Total   : constant Natural := Into.Count + Width;
      Pending : Natural := Total;
   begin
      Into.Bits := Into.Bits or Shift_Left (Unsigned_64 (Value), Into.Count);
      while Pending >= 8 loop
         pragma Loop_Invariant (Pending <= 39 and then Pending mod 8 = Total mod 8
                                and then Into.Next in Output'First .. Output'Last + 1);
         if Into.Next <= Output'Last then
            Output (Into.Next) := Character'Val (Into.Bits and 16#FF#);
            Into.Next := Into.Next + 1;
         else
            Into.Full := True;
         end if;
         Into.Bits := Shift_Right (Into.Bits, 8);
         Pending   := Pending - 8;
      end loop;
      Into.Count := Pending;
   end Put;

   --  Zero bits to the next byte boundary.
   procedure Align (Into : in out Writer; Output : in out String)
      with Pre  => Output'Last < Positive'Last and then Into.Next in Output'First .. Output'Last + 1,
           Post => Into.Next in Output'First .. Output'Last + 1 and then Into.Count = 0
   is
   begin
      if Into.Count > 0 then
         Put (Into, Output, 0, 8 - Into.Count);
      end if;
   end Align;

   ---------------------------------------------------------------------------------------------------------------
   --  blocks

   type Block_Kind is (Stored, Fixed, Dynamic);

   procedure Put_Stored
     (Into : in out Writer; Output : in out String; Data : String; Final : Boolean)
      with Pre  => Output'Last < Positive'Last and then Into.Next in Output'First .. Output'Last + 1
                   and then Data'First >= 1 and then Data'Last < Positive'Last and then Data'Last >= Data'First - 1,
           Post => Into.Next in Output'First .. Output'Last + 1
   is
      Start : Positive := Data'First;
   begin
      loop
         pragma Loop_Invariant (Into.Next in Output'First .. Output'Last + 1 and then Start >= Data'First
                                and then Start <= Data'Last + 1);
         declare
            Size : constant Natural := Natural'Min (Data'Last - Start + 1, 65_535);
            Last : constant Boolean := Size = Data'Last - Start + 1;
         begin
            Put (Into, Output, (if Final and then Last then 1 else 0), 1);
            Put (Into, Output, 0, 2);
            Align (Into, Output);
            Put (Into, Output, Unsigned_32 (Size), 16);
            Put (Into, Output, Unsigned_32 (Size) xor 16#FFFF#, 16);
            for Index in Start .. Start + Size - 1 loop
               pragma Loop_Invariant (Into.Next in Output'First .. Output'Last + 1);
               exit when Into.Full;
               Put (Into, Output, Character'Pos (Data (Index)), 8);
            end loop;
            exit when Last or else Into.Full;
            Start := Start + Size;
         end;
      end loop;
   end Put_Stored;

   --  The block of Work's first Count symbols, which stand for Data, as the smallest of the three kinds.
   procedure Put_Block
     (Work   : State;
      Count  : Natural;
      Data   : String;
      Final  : Boolean;
      Into   : in out Writer;
      Output : in out String)
      with Pre  => Output'Last < Positive'Last and then Count <= Block_Symbols
                   and then Into.Next in Output'First .. Output'Last + 1
                   and then Data'First >= 1 and then Data'Last < Positive'Last and then Data'Last >= Data'First - 1,
           Post => Into.Next in Output'First .. Output'Last + 1
   is
      Litlen_Count   : Count_Array (Litlen_Symbol) := [others => 0];
      Distance_Count : Count_Array (Distance_Symbol) := [others => 0];

      Litlen_Length   : Length_Array (Litlen_Symbol);
      Distance_Length : Length_Array (Distance_Symbol);
      Litlen_Code     : Code_Array (Litlen_Symbol);
      Distance_Code_Of : Code_Array (Distance_Symbol);

      --  The code lengths of both trees, run-length coded with symbols 16, 17 and 18 (3.2.7).
      Max_Runs   : constant := 286 + 30;
      Run_Symbol : array (1 .. Max_Runs) of Code_Length_Symbol := [others => 0];
      Run_Extra  : array (1 .. Max_Runs) of Unsigned_32 := [others => 0];
      Runs       : Natural range 0 .. Max_Runs := 0;
      Lengths_Count  : Count_Array (Code_Length_Symbol) := [others => 0];
      Lengths_Length : Length_Array (Code_Length_Symbol);
      Lengths_Code   : Code_Array (Code_Length_Symbol);

      Litlen_Total   : Positive range 257 .. 286 := 286;
      Distance_Total : Positive range 1 .. 30 := 30;
      Order_Total    : Positive range 4 .. 19 := 19;

      Kind : Block_Kind;

      --  Bits to write the symbols with these lengths, extra bits included.
      function Data_Cost (Litlens : Length_Array; Distances : Length_Array) return Unsigned_64
         with Pre => Litlens'First = 0 and then Litlens'Last >= 285 and then Distances'First = 0
                     and then Distances'Last >= 29
      is
         Result : Unsigned_64 := 0;
      begin
         for Symbol in Litlen_Symbol loop
            Result := Result + Unsigned_64 (Litlen_Count (Symbol)) * Unsigned_64 (Litlens (Symbol));
         end loop;
         for Symbol in Length_Symbol loop
            Result := Result + Unsigned_64 (Litlen_Count (257 + Symbol)) * Unsigned_64 (Length_Extra (Symbol));
         end loop;
         for Symbol in Distance_Symbol loop
            Result := Result + Unsigned_64 (Distance_Count (Symbol))
                                 * Unsigned_64 (Distances (Symbol) + Distance_Extra (Symbol));
         end loop;
         return Result;
      end Data_Cost;

      procedure Add_Run (Symbol : Code_Length_Symbol; Extra : Unsigned_32) is
      begin
         if Runs < Max_Runs then
            Runs := Runs + 1;
            Run_Symbol (Runs) := Symbol;
            Run_Extra (Runs)  := Extra;
            Lengths_Count (Symbol) := Lengths_Count (Symbol) + 1;
         end if;
      end Add_Run;

      procedure Put_Symbols (Litlens : Code_Array; Litlen_Widths : Length_Array;
                             Distances : Code_Array; Distance_Widths : Length_Array)
         with Pre => Litlens'First = 0 and then Litlens'Last >= 285 and then Litlen_Widths'First = 0
                     and then Litlen_Widths'Last >= 285 and then Distances'First = 0 and then Distances'Last >= 29
                     and then Distance_Widths'First = 0 and then Distance_Widths'Last >= 29
                     and then Output'Last < Positive'Last and then Count <= Block_Symbols
                     and then Into.Next in Output'First .. Output'Last + 1,
              Post => Into.Next in Output'First .. Output'Last + 1
      is
      begin
         for Index in 1 .. Count loop
            pragma Loop_Invariant (Into.Next in Output'First .. Output'Last + 1);
            exit when Into.Full;
            declare
               Length : constant Unsigned_16 := Work.Lengths (Index);
               Value  : constant Unsigned_16 := Work.Values (Index);
            begin
               if Length = 0 then
                  declare
                     Byte : constant Natural := Natural (Value and 16#FF#);
                  begin
                     Put (Into, Output, Litlens (Byte), Litlen_Widths (Byte));
                  end;
               else
                  declare
                     Match    : constant Match_Length :=
                       Natural'Max (Min_Match, Natural'Min (Natural (Length), Max_Match));
                     Symbol   : constant Length_Symbol := Length_Code (Match);
                     Distance : constant Match_Distance :=
                       Natural'Max (1, Natural'Min (Natural (Value), Window_Size));
                     Far      : constant Distance_Symbol := Distance_Code (Distance);
                  begin
                     Put (Into, Output, Litlens (257 + Symbol), Litlen_Widths (257 + Symbol));
                     Put (Into, Output, Unsigned_32 (Match) - Unsigned_32 (Length_Base (Symbol)),
                          Length_Extra (Symbol));
                     Put (Into, Output, Distances (Far), Distance_Widths (Far));
                     Put (Into, Output, Unsigned_32 (Distance) - Unsigned_32 (Distance_Base (Far)),
                          Distance_Extra (Far));
                  end;
               end if;
            end;
         end loop;
         Put (Into, Output, Litlens (End_Of_Block), Litlen_Widths (End_Of_Block));
      end Put_Symbols;

   begin
      --  How often each symbol is used.
      for Index in 1 .. Count loop
         if Work.Lengths (Index) = 0 then
            Litlen_Count (Natural (Work.Values (Index) and 16#FF#)) :=
              Litlen_Count (Natural (Work.Values (Index) and 16#FF#)) + 1;
         else
            declare
               Match  : constant Match_Length :=
                 Natural'Max (Min_Match, Natural'Min (Natural (Work.Lengths (Index)), Max_Match));
               Symbol : constant Distance_Symbol :=
                 Distance_Code (Natural'Max (1, Natural'Min (Natural (Work.Values (Index)), Window_Size)));
            begin
               Litlen_Count (257 + Length_Code (Match)) := Litlen_Count (257 + Length_Code (Match)) + 1;
               Distance_Count (Symbol) := Distance_Count (Symbol) + 1;
            end;
         end if;
      end loop;
      Litlen_Count (End_Of_Block) := 1;

      Build_Lengths (Litlen_Count, 15, Litlen_Length);
      Build_Lengths (Distance_Count, 15, Distance_Length);
      while Litlen_Total > 257 and then Litlen_Length (Litlen_Total - 1) = 0 loop
         Litlen_Total := Litlen_Total - 1;
      end loop;
      while Distance_Total > 1 and then Distance_Length (Distance_Total - 1) = 0 loop
         Distance_Total := Distance_Total - 1;
      end loop;

      --  Both trees' lengths as one sequence, run-length coded.
      declare
         Total : constant Positive := Litlen_Total + Distance_Total;
         function Length_At (Index : Natural) return Code_Length is
           (if Index < Litlen_Total then Litlen_Length (Index)
            elsif Index - Litlen_Total in Distance_Symbol then Distance_Length (Index - Litlen_Total) else 0);
         Index : Natural := 0;
      begin
         while Index < Total loop
            pragma Loop_Invariant (Index < Total);
            pragma Loop_Variant (Increases => Index);
            declare
               Length : constant Code_Length := Length_At (Index);
               Run    : Positive := 1;
            begin
               while Index + Run < Total and then Length_At (Index + Run) = Length
                 and then Run < (if Length = 0 then 138 else 7)
               loop
                  pragma Loop_Invariant (Run in 1 .. 137 and then Index + Run < Total);
                  Run := Run + 1;
               end loop;
               if Length = 0 and then Run >= 11 then
                  Add_Run (18, Unsigned_32 (Run - 11));
               elsif Length = 0 and then Run >= 3 then
                  Add_Run (17, Unsigned_32 (Run - 3));
               elsif Length /= 0 and then Run >= 4 then
                  Add_Run (Length, 0);
                  Add_Run (16, Unsigned_32 (Run - 4));
               else
                  for Times in 1 .. Run loop
                     Add_Run (Length, 0);
                  end loop;
               end if;
               Index := Index + Run;
            end;
         end loop;
      end;
      Build_Lengths (Lengths_Count, 7, Lengths_Length);
      while Order_Total > 4 and then Lengths_Length (Code_Length_Order (Order_Total - 1)) = 0 loop
         Order_Total := Order_Total - 1;
      end loop;

      --  The cheapest kind.
      declare
         Dynamic_Cost : Unsigned_64 :=
           3 + 14 + 3 * Unsigned_64 (Order_Total) + Data_Cost (Litlen_Length, Distance_Length)
           + 2 * Unsigned_64 (Lengths_Count (16)) + 3 * Unsigned_64 (Lengths_Count (17))
           + 7 * Unsigned_64 (Lengths_Count (18));
         Fixed_Cost   : constant Unsigned_64 := 3 + Data_Cost (Fixed_Litlen_Length, Fixed_Distance_Length);
         Stored_Cost  : constant Unsigned_64 :=
           (Unsigned_64 (Data'Length) / 65_535 + 1) * 48 + 8 * Unsigned_64 (Data'Length);
      begin
         for Symbol in Code_Length_Symbol loop
            Dynamic_Cost := Dynamic_Cost + Unsigned_64 (Lengths_Count (Symbol)) * Unsigned_64 (Lengths_Length (Symbol));
         end loop;
         Kind := (if Stored_Cost < Fixed_Cost and then Stored_Cost < Dynamic_Cost then Stored
                  elsif Fixed_Cost <= Dynamic_Cost then Fixed else Dynamic);
      end;

      case Kind is
         when Stored =>
            Put_Stored (Into, Output, Data, Final);
         when Fixed =>
            Put (Into, Output, (if Final then 1 else 0), 1);
            Put (Into, Output, 1, 2);
            Put_Symbols (Fixed_Litlen_Code, Fixed_Litlen_Length, Fixed_Distance_Code, Fixed_Distance_Length);
         when Dynamic =>
            Make_Codes (Litlen_Length, Litlen_Code);
            Make_Codes (Distance_Length, Distance_Code_Of);
            Make_Codes (Lengths_Length, Lengths_Code);
            Put (Into, Output, (if Final then 1 else 0), 1);
            Put (Into, Output, 2, 2);
            Put (Into, Output, Unsigned_32 (Litlen_Total - 257), 5);
            Put (Into, Output, Unsigned_32 (Distance_Total - 1), 5);
            Put (Into, Output, Unsigned_32 (Order_Total - 4), 4);
            for Index in 0 .. Order_Total - 1 loop
               pragma Loop_Invariant (Into.Next in Output'First .. Output'Last + 1);
               Put (Into, Output, Unsigned_32 (Lengths_Length (Code_Length_Order (Index))), 3);
            end loop;
            for Index in 1 .. Runs loop
               pragma Loop_Invariant (Into.Next in Output'First .. Output'Last + 1);
               declare
                  Symbol : constant Code_Length_Symbol := Run_Symbol (Index);
               begin
                  Put (Into, Output, Lengths_Code (Symbol), Lengths_Length (Symbol));
                  case Symbol is
                     when 16 => Put (Into, Output, Run_Extra (Index) and 3, 2);
                     when 17 => Put (Into, Output, Run_Extra (Index) and 7, 3);
                     when 18 => Put (Into, Output, Run_Extra (Index) and 127, 7);
                     when others => null;
                  end case;
               end;
            end loop;
            Put_Symbols (Litlen_Code, Litlen_Length, Distance_Code_Of, Distance_Length);
      end case;
   end Put_Block;

   ---------------------------------------------------------------------------------------------------------------
   --  matching

   --  Hash tables smaller than the most are used for small inputs, so that clearing one costs little.
   subtype Hash_Width is Natural range 8 .. Hash_Bits;

   function Hash_At (Input : String; Position : Positive; Width : Hash_Width) return Hash_Index
      with Pre => Input'Length >= 3 and then Position >= Input'First and then Position <= Input'Last - 2, Inline
   is
      Value : constant Unsigned_32 :=
        Unsigned_32 (Character'Pos (Input (Position)))
        or Shift_Left (Unsigned_32 (Character'Pos (Input (Position + 1))), 8)
        or Shift_Left (Unsigned_32 (Character'Pos (Input (Position + 2))), 16);
   begin
      return Hash_Index (Shift_Right (Value * 2_654_435_761, 32 - Width));
   end Hash_At;

   --  The offset of Position from Input's start, counting from 1.
   function Offset_Of (Input : String; Position : Positive) return Chain_Offset is
     (Chain_Offset (Position - Input'First + 1))
      with Pre => Position in Input'Range;

   procedure Insert (Work : in out State; Input : String; Position : Positive; Hash : Hash_Index)
      with Pre => Position in Input'Range, Inline
   is
      Offset : constant Chain_Offset := Offset_Of (Input, Position);
      Latest : constant Chain_Offset := Work.Head (Hash);
   begin
      Work.Chain (Window_Index ((Offset - 1) mod Window_Size)) :=
        (if Latest /= 0 and then Latest < Offset and then Offset - Latest <= Window_Size - 1
         then Unsigned_16 (Offset - Latest) else 0);
      Work.Head (Hash) := Offset;
   end Insert;

   --  The longest earlier match for the bytes at Position, if one is at least Min_Match long: Length 0 if not.
   procedure Find
     (Work     : State;
      Input    : String;
      Position : Positive;
      Hash     : Hash_Index;
      Length   : out Natural;
      Distance : out Natural)
      with Pre  => Input'Length >= 3 and then Position >= Input'First and then Position <= Input'Last - 2,
           Post => (Length = 0 or else (Length in Min_Match .. Max_Match
                                        and then Length <= Input'Last - Position + 1
                                        and then Distance in 1 .. Window_Size - 1))
   is
      Room      : constant Natural := Natural'Min (Max_Match, Input'Last - Position + 1);
      Offset    : constant Chain_Offset := Offset_Of (Input, Position);
      Candidate : Chain_Offset := Work.Head (Hash);
      Best      : Natural := Min_Match - 1;
   begin
      Length   := 0;
      Distance := 0;
      for Tries in 1 .. Max_Chain loop
         pragma Loop_Invariant (Room <= Max_Match and then Room <= Input'Last - Position + 1);
         pragma Loop_Invariant (Best in Min_Match - 1 .. Room
                                and then (Length = 0 or else (Length = Best and then Length >= Min_Match
                                                              and then Distance in 1 .. Window_Size - 1)));
         exit when Candidate = 0 or else Candidate >= Offset or else Offset - Candidate >= Window_Size
           or else Best >= Room;
         --  The exit bounds the chain offset; state it where the provers can use it for the index checks.
         pragma Assert (Candidate >= 1 and then Candidate < Offset and then Best < Room);
         pragma Assert (Best <= Input'Last - Position);
         declare
            Start : constant Positive := Input'First + Natural (Candidate) - 1;
            Run   : Natural := 0;
         begin
            if Input (Start + Best) = Input (Position + Best) then
               while Run < Room and then Input (Start + Run) = Input (Position + Run) loop
                  pragma Loop_Invariant (Run < Room);
                  Run := Run + 1;
               end loop;
               if Run > Best then
                  pragma Assert (Start < Position and then Position - Start = Natural (Offset - Candidate));
                  Best     := Run;
                  Length   := Run;
                  Distance := Position - Start;
                  exit when Run >= Nice_Length;
               end if;
            end if;
         end;
         declare
            Step : constant Unsigned_16 := Work.Chain (Window_Index ((Candidate - 1) mod Window_Size));
         begin
            exit when Step = 0 or else Chain_Offset (Step) >= Candidate;
            Candidate := Candidate - Chain_Offset (Step);
         end;
      end loop;
   end Find;

   ---------------------------------------------------------------------------------------------------------------

   procedure Compress
     (Work   : in out State;
      Input  : String;
      Output : in out String;
      Last   : out Natural;
      Fits   : out Boolean)
   is
      Into        : Writer := (Bits => 0, Count => 0, Next => Output'First, Full => False);
      Top         : constant array (Hash_Width) of Hash_Index :=
        [8 => 255, 9 => 511, 10 => 1023, 11 => 2047, 12 => 4095, 13 => 8191, 14 => 16383, 15 => 32767];
      Count       : Natural range 0 .. Block_Symbols := 0;   --  symbols in the block so far
      Block_Start : Positive := Input'First;                 --  the first byte the block stands for

      --  Write the block, which stands for the bytes before Next.
      procedure Flush (Next : Positive; Final : Boolean)
         with Pre  => Input'First >= 1 and then Input'Last < Positive'Last - 512 and then Output'Last < Positive'Last
                      and then Block_Start >= Input'First and then Next >= Block_Start and then Next <= Input'Last + 1
                      and then Into.Next in Output'First .. Output'Last + 1,
              Post => Count = 0 and then Into.Next in Output'First .. Output'Last + 1 and then Block_Start = Next
      is
      begin
         Put_Block (Work, Count, Input (Block_Start .. Next - 1), Final, Into, Output);
         Count       := 0;
         Block_Start := Next;
      end Flush;

      --  A symbol standing for the bytes before Next; the block is written when full.
      procedure Add (Length : Natural; Value : Natural; Next : Positive)
         with Pre  => Input'First >= 1 and then Input'Last < Positive'Last - 512 and then Output'Last < Positive'Last
                      and then Length <= Max_Match and then Value <= Window_Size
                      and then Block_Start >= Input'First and then Next >= Block_Start
                      and then Next <= Input'Last + 1 and then Count < Block_Symbols
                      and then Into.Next in Output'First .. Output'Last + 1,
              Post => Count < Block_Symbols and then Into.Next in Output'First .. Output'Last + 1
                      and then Block_Start <= Next and then Block_Start >= Input'First
      is
      begin
         Count := Count + 1;
         Work.Lengths (Count) := Unsigned_16 (Length);
         Work.Values (Count)  := Unsigned_16 (Value);
         if Count = Block_Symbols then
            Flush (Next, Final => False);
         end if;
      end Add;

      Position      : Positive := Input'First;
      Pending       : Boolean := False;   --  the byte before Position waits: a literal, or where Held starts
      Held_Length   : Natural := 0;
      Held_Distance : Natural := 0;
      Width         : Hash_Width := Hash_Width'First;
   begin
      while Width < Hash_Bits and then 2 ** Width < Input'Length loop
         Width := Width + 1;
      end loop;
      Work.Head (0 .. Top (Width)) := [others => 0];
      while Position <= Input'Last loop
         pragma Loop_Invariant (Position >= Input'First and then Position <= Input'Last + 1);
         pragma Loop_Invariant (Position > Input'First or else not Pending);
         pragma Loop_Invariant (Block_Start >= Input'First);
         pragma Loop_Invariant (Block_Start <= (if Pending then Position - 1 else Position));
         pragma Loop_Invariant (Count < Block_Symbols and then Into.Next in Output'First .. Output'Last + 1);
         pragma Loop_Invariant
           (Held_Length = 0 or else (Pending and then Held_Length in Min_Match .. Max_Match
                                     and then Held_Length <= Input'Last - Position + 2
                                     and then Held_Distance in 1 .. Window_Size - 1));
         pragma Loop_Variant (Increases => Position);
         exit when Into.Full;
         declare
            Length   : Natural := 0;
            Distance : Natural := 0;
         begin
            if Input'Length >= 3 and then Position <= Input'Last - 2 then
               declare
                  Hash : constant Hash_Index := Hash_At (Input, Position, Width);
               begin
                  if not Pending or else Held_Length < Lazy_Limit then
                     Find (Work, Input, Position, Hash, Length, Distance);
                  end if;
                  Insert (Work, Input, Position, Hash);
               end;
            end if;
            if Pending and then Held_Length > 0 and then Length <= Held_Length then
               --  The held match is at least as good: take it, and index the positions it covers.
               Add (Held_Length, Held_Distance, Position - 1 + Held_Length);
               for Covered in Position + 1 .. Position - 2 + Held_Length loop
                  pragma Loop_Invariant (Count < Block_Symbols);
                  if Input'Length >= 3 and then Covered <= Input'Last - 2 then
                     Insert (Work, Input, Covered, Hash_At (Input, Covered, Width));
                  end if;
               end loop;
               Position := Position - 1 + Held_Length;
               Pending  := False;
               Held_Length := 0;
            else
               if Pending then
                  Add (0, Character'Pos (Input (Position - 1)), Position);
               end if;
               Pending       := True;
               Held_Length   := Length;
               Held_Distance := Distance;
               Position      := Position + 1;
            end if;
         end;
      end loop;
      if not Into.Full then
         if Pending then
            if Held_Length > 0 then
               Add (Held_Length, Held_Distance, Input'Last + 1);
            else
               Add (0, Character'Pos (Input (Input'Last)), Input'Last + 1);
            end if;
         end if;
         pragma Warnings (GNATprove, Off, "* is set by * but not used after the call",
                          Reason => "the last block: what Flush resets is not needed again");
         Flush (Input'Last + 1, Final => True);
         pragma Warnings (GNATprove, On, "* is set by * but not used after the call");
         Align (Into, Output);
      end if;
      Fits := not Into.Full;
      Last := Into.Next - 1;
   end Compress;

end Sparrow.Deflate;
