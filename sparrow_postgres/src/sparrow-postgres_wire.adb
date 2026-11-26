with Ada.Unchecked_Conversion;

package body Sparrow.Postgres_Wire with SPARK_Mode is

   ----------
   -- Byte --
   ----------

   function Byte (Data : String; Position : Positive) return Unsigned_32 is
     (Unsigned_32 (Character'Pos (Data (Position))))
      with Inline, Pre => Position in Data'Range;

   ----------
   -- Word --
   ----------

   function Word (Data : String; Position : Positive) return Unsigned_32 is
     (Shift_Left (Byte (Data, Position), 24) or Shift_Left (Byte (Data, Position + 1), 16)
      or Shift_Left (Byte (Data, Position + 2), 8) or Byte (Data, Position + 3));

   -----------
   -- Short --
   -----------

   function Short (Data : String; Position : Positive) return Natural is
     (Natural (Byte (Data, Position)) * 256 + Natural (Byte (Data, Position + 1)));

   -----------------
   -- Signed_Word --
   -----------------

   function Signed_Word (Data : String; Position : Positive) return Long_Long_Integer is
     (Long_Long_Integer (Word (Data, Position)) - (if Word (Data, Position) >= 2 ** 31 then 2 ** 32 else 0));

   -------------------------
   -- Signed_Double_Word --
   -------------------------

   function Signed_Double_Word (Data : String; Position : Positive) return Long_Long_Integer is
      Bits : constant Unsigned_64 := Shift_Left (Unsigned_64 (Word (Data, Position)), 32)
                                     or Unsigned_64 (Word (Data, Position + 4));
   begin
      return (if Bits >= 2 ** 63 then -Long_Long_Integer (not Bits) - 1 else Long_Long_Integer (Bits));
   end Signed_Double_Word;

   -----------------
   -- Next_Column --
   -----------------

   procedure Next_Column
     (Data     : String;
      Last     : Natural;
      Position : in out Positive;
      Item     : out Field;
      Valid    : out Boolean)
   is
      Length : Long_Long_Integer;
   begin
      Item  := Null_Field;
      Valid := False;
      if Position > Last - 3 or else Last < 4 then
         return;
      end if;
      Length := Signed_Word (Data, Position);
      if Length < Null_Length or else Length > Long_Long_Integer (Last - (Position + 4) + 1) then
         return;
      end if;
      Item     := (Position => Position + 4, Length => Integer (Length));
      Position := Position + 4 + Integer'Max (Item.Length, 0);
      Valid    := True;
   end Next_Column;

   -----------------
   -- Error_Field --
   -----------------

   function Error_Field (Data : String; First : Positive; Last : Natural; Code : Character) return String is
      Position : Positive := First;
   begin
      while Position <= Last and then Data (Position) /= ASCII.NUL loop
         pragma Loop_Invariant (Position in First .. Last);
         pragma Loop_Variant (Increases => Position);
         declare
            Field_Code : constant Character := Data (Position);
            Terminator : Positive := Position + 1;
         begin
            while Terminator <= Last and then Data (Terminator) /= ASCII.NUL loop
               pragma Loop_Invariant (Terminator in Position + 1 .. Last);
               pragma Loop_Variant (Increases => Terminator);
               Terminator := Terminator + 1;
            end loop;
            if Field_Code = Code then
               return Data (Position + 1 .. Terminator - 1);
            end if;
            exit when Terminator >= Last;
            Position := Terminator + 1;
         end;
      end loop;
      return "";
   end Error_Field;

   ----------
   -- Text --
   ----------

   function Text (Data : String; Item : Field) return String is
     (if Inside (Data, Item) then Data (Item.Position .. Item.Position + Item.Length - 1) else "");

   -------------------
   -- Integer_Value --
   -------------------

   function Integer_Value (Data : String; Item : Field) return Long_Long_Integer is
   begin
      if not Inside (Data, Item) then
         return 0;
      end if;

      case Item.Length is
         when 2 =>
            declare
               Value : constant Natural := Short (Data, Item.Position);
            begin
               return Long_Long_Integer (Value) - (if Value >= 2 ** 15 then 2 ** 16 else 0);
            end;
         when 4 =>
            return Signed_Word (Data, Item.Position);
         when 8 =>
            return Signed_Double_Word (Data, Item.Position);
         when others =>
            return 0;
      end case;
   end Integer_Value;

   -------------------
   -- Boolean_Value --
   -------------------

   function Boolean_Value (Data : String; Item : Field) return Boolean is
     (Inside (Data, Item) and then Item.Length >= 1 and then Data (Item.Position) /= ASCII.NUL);

   -----------------
   -- Float_Value --
   -----------------

   ------------------
   -- Float_4_Value --
   ------------------

   --  Unchecked_Conversion is not in SPARK; the spec's Post is what callers rely on.
   function Float_4_Value (Bits : Unsigned_32) return Long_Float with SPARK_Mode => Off is
      function To_Float is new Ada.Unchecked_Conversion (Unsigned_32, Float);
      Value : constant Float := To_Float (Bits);
   begin
      return (if Value'Valid then Long_Float (Value) else 0.0);
   end Float_4_Value;

   ------------------
   -- Float_8_Value --
   ------------------

   function Float_8_Value (Bits : Unsigned_64) return Long_Float with SPARK_Mode => Off is
      function To_Long_Float is new Ada.Unchecked_Conversion (Unsigned_64, Long_Float);
      Value : constant Long_Float := To_Long_Float (Bits);
   begin
      return (if Value'Valid then Value else 0.0);
   end Float_8_Value;

   -----------------
   -- Float_Value --
   -----------------

   function Float_Value (Data : String; Item : Field) return Long_Float is
   begin
      if not Inside (Data, Item) then
         return 0.0;
      end if;

      case Item.Length is
         when 4 =>
            return Float_4_Value (Word (Data, Item.Position));
         when 8 =>
            return Float_8_Value (Shift_Left (Unsigned_64 (Word (Data, Item.Position)), 32)
                                  or Unsigned_64 (Word (Data, Item.Position + 4)));
         when others =>
            return 0.0;
      end case;
   end Float_Value;

   -------------------
   -- Element_Count --
   -------------------

   function Element_Count (Data : String; Item : Field) return Natural is begin
      if not Inside (Data, Item) or else Item.Length < Array_Header or else Word (Data, Item.Position) = 0 then
         return 0;   --  empty arrays have zero dimensions and no header beyond them
      end if;
      return Natural (Unsigned_32'Min (Word (Data, Item.Position + 12), Unsigned_32 (Natural'Last)));
   end Element_Count;

   -------------
   -- Element --
   -------------

   function Element (Data : String; Item : Field; Index : Positive) return Field is
      Last     : Natural;
      Position : Positive;
      Current  : Field;
      Valid    : Boolean;
   begin
      if not Inside (Data, Item) or else Item.Length < Array_Header then
         return Null_Field;
      end if;
      Last     := Item.Position + Item.Length - 1;
      Position := Item.Position + Array_Header;
      for Count in 1 .. Index loop
         pragma Loop_Invariant (Position <= Last + 1 and then Last <= Data'Last);
         Next_Column (Data, Last, Position, Current, Valid);
         if not Valid then
            return Null_Field;
         end if;
         if Count = Index then
            return Current;
         end if;
      end loop;
      return Null_Field;
   end Element;

end Sparrow.Postgres_Wire;
