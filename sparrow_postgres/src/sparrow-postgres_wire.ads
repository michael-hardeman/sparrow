--  Decoding Postgres protocol bytes (binary format) held in a receive buffer. Every length the server sends is
--  checked against the bytes around it once, when a row is framed; the value accessors are total, so a field
--  that does not fit reads as NULL, 0 or "" instead of reaching outside the buffer.
--
--  Sparrow.Postgres is the interface to use; this unit is its decoder, kept apart so it can be proved alone.
--
--  SPARK: free of run-time errors, whatever bytes arrive.
with Interfaces; use Interfaces;

package Sparrow.Postgres_Wire with SPARK_Mode is

   Null_Length : constant := -1;

   Max_Buffer_Length : constant := 2 ** 30;

   --  A receive buffer as the decoder sees it.
   function Framed (Data : String) return Boolean is (Data'First = 1 and then Data'Last in 0 .. Max_Buffer_Length);

   --  A value inside the buffer: Length bytes from Position, or SQL NULL.
   type Field is record
      Position : Positive := 1;
      Length   : Integer range Null_Length .. Integer'Last := Null_Length;
   end record;

   Null_Field : constant Field := (Position => 1, Length => Null_Length);

   function Is_Null (Item : Field) return Boolean is (Item.Length = Null_Length);

   --  Whether Item is a value whose bytes lie inside Data.
   function Inside (Data : String; Item : Field) return Boolean is
     (Item.Length >= 0 and then Item.Position >= Data'First and then Item.Length <= Data'Last - Item.Position + 1)
      with Pre => Framed (Data);

   --  Big-endian integers at Position.
   function Word (Data : String; Position : Positive) return Unsigned_32
      with Pre => Framed (Data) and then Position <= Data'Last - 3;

   function Short (Data : String; Position : Positive) return Natural
      with Pre => Framed (Data) and then Position <= Data'Last - 1, Post => Short'Result < 2 ** 16;

   --  The next column of a DataRow at Position: a signed length (-1 for NULL), then the bytes. Valid when the
   --  length is -1 or more and the bytes end by Last; Position then moves past them.
   procedure Next_Column
     (Data     : String;
      Last     : Natural;
      Position : in out Positive;
      Item     : out Field;
      Valid    : out Boolean)
      with Pre  => Framed (Data) and then Last <= Data'Last,
           Post => (if Valid
                    then (Is_Null (Item) or else Inside (Data, Item))
                          and then Position <= Last + 1
                          and then Position > Position'Old
                    else Item = Null_Field and then Position = Position'Old);

   --  Field Code ('C' the SQLSTATE, 'M' the message) of an ErrorResponse whose fields are Data (First .. Last).
   function Error_Field (Data : String; First : Positive; Last : Natural; Code : Character) return String
      with Pre => Framed (Data) and then Last <= Data'Last;

   Array_Header : constant := 20;   --  dimensions, flags, element type, length, lower bound

   --  Signed big-endian integers, named by the value accessors' contracts.
   function Signed_Word (Data : String; Position : Positive) return Long_Long_Integer
      with Pre => Framed (Data) and then Position <= Data'Last - 3;

   function Signed_Double_Word (Data : String; Position : Positive) return Long_Long_Integer
      with Pre => Framed (Data) and then Position <= Data'Last - 7;

   --  An all-ones exponent is the bit pattern the body's 'Valid check rejects as NaN or infinity. SPARK assumes
   --  'Valid always true, so the contract states the same condition on the bits instead.
   function Finite_4 (Bits : Unsigned_32) return Boolean is
     ((Shift_Right (Bits, 23) and 16#FF#) /= 16#FF#);

   function Finite_8 (Bits : Unsigned_64) return Boolean is
     ((Shift_Right (Bits, 52) and 16#7FF#) /= 16#7FF#);

   --  A float decoded from its bits, or 0.0 when the pattern is not finite. Unchecked_Conversion keeps these
   --  two outside SPARK; their Post is the contract Float_Value's Post builds on.
   function Float_4_Value (Bits : Unsigned_32) return Long_Float
      with Post => (if not Finite_4 (Bits) then Float_4_Value'Result = 0.0);

   function Float_8_Value (Bits : Unsigned_64) return Long_Float
      with Post => (if not Finite_8 (Bits) then Float_8_Value'Result = 0.0);

   --  Values: total over any field.
   function Text (Data : String; Item : Field) return String
      with Pre  => Framed (Data),
           Post => Text'Result = (if Inside (Data, Item)
                                  then Data (Item.Position .. Item.Position + Item.Length - 1)
                                  else "");

   --  int2, int4 or int8 by the field's length; 0 for any other length.
   function Integer_Value (Data : String; Item : Field) return Long_Long_Integer
      with Pre  => Framed (Data),
           Post =>
             Integer_Value'Result =
               (if not Inside (Data, Item) then 0
                elsif Item.Length = 2 then
                  Long_Long_Integer (Short (Data, Item.Position))
                    - (if Short (Data, Item.Position) >= 2 ** 15 then 2 ** 16 else 0)
                elsif Item.Length = 4 then Signed_Word (Data, Item.Position)
                elsif Item.Length = 8 then Signed_Double_Word (Data, Item.Position)
                else 0);

   function Boolean_Value (Data : String; Item : Field) return Boolean
      with Pre  => Framed (Data),
           Post => Boolean_Value'Result =
             (Inside (Data, Item) and then Item.Length >= 1 and then Data (Item.Position) /= ASCII.NUL);

   --  float4 or float8 by the field's length; 0.0 for any other length or a value that is not finite.
   function Float_Value (Data : String; Item : Field) return Long_Float
      with Pre  => Framed (Data),
           Post =>
             Float_Value'Result =
               (if not Inside (Data, Item) then 0.0
                elsif Item.Length = 4 then Float_4_Value (Word (Data, Item.Position))
                elsif Item.Length = 8 then
                  Float_8_Value (Shift_Left (Unsigned_64 (Word (Data, Item.Position)), 32)
                                 or Unsigned_64 (Word (Data, Item.Position + 4)))
                else 0.0);

   --  Binary arrays (one dimension): dimensions, has-nulls flag, element type, then length and lower bound, then
   --  each element as a length and its bytes.
   function Element_Count (Data : String; Item : Field) return Natural
      with Pre  => Framed (Data),
           Post =>
             Element_Count'Result =
               (if not Inside (Data, Item) or else Item.Length < Array_Header
                   or else Word (Data, Item.Position) = 0
                then 0
                else Natural (Unsigned_32'Min (Word (Data, Item.Position + 12),
                                               Unsigned_32 (Natural'Last))));

   --  Element Index (from 1); a NULL field when the array has no such element or its framing is broken.
   function Element (Data : String; Item : Field; Index : Positive) return Field
      with Pre  => Framed (Data),
           Post => Is_Null (Element'Result) or else Inside (Data, Element'Result);

end Sparrow.Postgres_Wire;
