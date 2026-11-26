with Ada.Strings.Fixed;
with Ada.Text_IO;
with Sparrow.Encoding;
with Sparrow.Times;

package body Sparrow.Postgres.Queries is

   use Ada.Strings.Unbounded;

   --  A float as a person writes it: no exponent for ordinary sizes, no trailing zeros.
   function Float_Image (Number : Long_Float) return String is
      package Float_Text is new Ada.Text_IO.Float_IO (Long_Float);
      Text : String (1 .. 64);
      Last : Natural;
   begin
      if Number = Long_Float'Truncation (Number) and then abs Number < 1.0E15 then
         return Encoding.Decimal_Image (Long_Long_Integer (Number));
      elsif abs Number >= 1.0E15 or else abs Number < 1.0E-6 then
         Float_Text.Put (Text, Number, Aft => 15, Exp => 3);
         return Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
      end if;
      Float_Text.Put (Text, Number, Aft => 15, Exp => 0);
      Last := Text'Last;
      while Text (Last) = '0' and then Text (Last - 1) /= '.' loop
         Last := Last - 1;
      end loop;
      return Ada.Strings.Fixed.Trim (Text (1 .. Last), Ada.Strings.Both);
   end Float_Image;

   function "+" (Value : UTF8_String) return Parameter is
     ((Kind => Text_Kind, Content => To_Unbounded_String (String (Value)), others => <>));
   function "+" (Value : Long_Long_Integer) return Parameter is ((Kind => Integer_Kind, Whole => Value, others => <>));
   function "+" (Value : Integer) return Parameter is (+Long_Long_Integer (Value));
   function "+" (Value : Boolean) return Parameter is ((Kind => Boolean_Kind, Flag => Value, others => <>));
   function "+" (Value : Long_Float) return Parameter is ((Kind => Float_Kind, Real => Value, others => <>));
   function Bytes (Value : String) return Parameter is
     ((Kind => Bytes_Kind, Content => To_Unbounded_String (Value), others => <>));
   function Timestamp (Value : Unix_Microseconds) return Parameter is
     ((Kind => Timestamp_Kind, Whole => Long_Long_Integer (Value), others => <>));
   function Null_Value return Parameter is ((Kind => Null_Kind, others => <>));

   procedure Query
     (This : in out Connection; Prepared : Statement; Parameters : Parameter_List; Result : out Statement_Result)
   is begin
      Bind (This, Prepared);
      for Each of Parameters loop
         case Each.Kind is
            when Text_Kind      => Add_Parameter (This, UTF8_String (To_String (Each.Content)));
            when Integer_Kind   => Add_Parameter (This, Each.Whole);
            when Boolean_Kind   => Add_Parameter (This, Each.Flag);
            when Float_Kind     => Add_Parameter (This, Each.Real);
            when Bytes_Kind     => Add_Bytes (This, To_String (Each.Content));
            when Timestamp_Kind => Add_Timestamp (This, Unix_Microseconds (Each.Whole));
            when Null_Kind      => Add_Null (This);
         end case;
      end loop;
      Execute (This);
      begin
         Fetch (This, Result);
      exception
         when Connection_Error =>
            Discard_Unsent (This);   --  wrong parameters leave the pipeline unsendable: start the next one clean
            raise;
      end;
   end Query;

   procedure Query (This : in out Connection; Prepared : Statement; Result : out Statement_Result) is begin
      Query (This, Prepared, No_Parameter_Values, Result);
   end Query;

   ---------------------------------------------------------------------------------------------------------------
   --  Rows

   function Number (This : Row) return Positive is (This.Position);

   function Field (This : Row; Column : Positive) return Postgres.Field is
     (Field_At (This.Db.all, This.Result, This.Position, Column));

   function Field (This : Row; Column : String) return Postgres.Field is
      Position : constant Natural := Column_Of (This.Db.all, This.Result, Column);
   begin
      if Position = 0 then
         raise Constraint_Error with "the result has no column named """ & Column & """";
      end if;
      return Field (This, Position);
   end Field;

   function Is_Null (This : Row; Column : String) return Boolean is (Is_Null (Field (This, Column)));
   function Text (This : Row; Column : String) return UTF8_String is (Text (This.Db.all, Field (This, Column)));
   function Bytes (This : Row; Column : String) return String is (Bytes (This.Db.all, Field (This, Column)));
   function Integer_Value (This : Row; Column : String) return Long_Long_Integer is
     (Integer_Value (This.Db.all, Field (This, Column)));
   function Boolean_Value (This : Row; Column : String) return Boolean is
     (Boolean_Value (This.Db.all, Field (This, Column)));
   function Float_Value (This : Row; Column : String) return Long_Float is
     (Float_Value (This.Db.all, Field (This, Column)));
   function Timestamp_Value (This : Row; Column : String) return Unix_Microseconds is
     (Timestamp_Value (This.Db.all, Field (This, Column)));

   function Is_Null (This : Row; Column : Positive) return Boolean is (Is_Null (Field (This, Column)));
   function Text (This : Row; Column : Positive) return UTF8_String is (Text (This.Db.all, Field (This, Column)));
   function Bytes (This : Row; Column : Positive) return String is (Bytes (This.Db.all, Field (This, Column)));
   function Integer_Value (This : Row; Column : Positive) return Long_Long_Integer is
     (Integer_Value (This.Db.all, Field (This, Column)));
   function Boolean_Value (This : Row; Column : Positive) return Boolean is
     (Boolean_Value (This.Db.all, Field (This, Column)));
   function Float_Value (This : Row; Column : Positive) return Long_Float is
     (Float_Value (This.Db.all, Field (This, Column)));
   function Timestamp_Value (This : Row; Column : Positive) return Unix_Microseconds is
     (Timestamp_Value (This.Db.all, Field (This, Column)));

   function Has_Element (Position : Row) return Boolean is
     (Position.Db /= null and then Position.Position in 1 .. Position.Result.Row_Count);

   --  In a package of its own, so that First and Next are primitive of the iterator only (Row is tagged too).
   package Walking is
      type Row_Walk is new Row_Iterators.Forward_Iterator with record
         Db     : Connection_View;
         Result : Statement_Result;
      end record;

      overriding function First (Object : Row_Walk) return Row is
        ((Db => Object.Db, Result => Object.Result, Position => 1));

      overriding function Next (Object : Row_Walk; Position : Row) return Row is
        ((Db => Object.Db, Result => Object.Result, Position => Position.Position + 1));
   end Walking;

   function Rows (This : Connection; Result : Statement_Result) return Row_Iterators.Forward_Iterator'Class is
     (Walking.Row_Walk'(Db => This'Unrestricted_Access, Result => Result));   --  Connection is limited: by reference

   ---------------------------------------------------------------------------------------------------------------
   --  Result_Reader

   function Reader (This : Connection; Result : Statement_Result) return Result_Reader is
     ((Db => This'Unrestricted_Access, Result => Result, Position => 0));

   function Next_Row (From : in out Result_Reader) return Boolean is
   begin
      if From.Position >= From.Result.Row_Count then
         return False;
      end if;
      From.Position := From.Position + 1;
      return True;
   end Next_Row;

   function Column_Count (From : Result_Reader) return Natural is (From.Result.Column_Count);

   function On_Row (From : Result_Reader) return Boolean is
     (From.Position in 1 .. From.Result.Row_Count);

   function Column_Name (From : Result_Reader; Column : Positive) return String is
     (Column_Name (From.Db.all, From.Result, Column));

   function Current (From : Result_Reader; Column : Positive) return Postgres.Field is
     (Field_At (From.Db.all, From.Result, Positive'Max (1, From.Position), Column));

   function Is_Null (From : Result_Reader; Column : Positive) return Boolean is
     (From.Position = 0 or else Is_Null (Current (From, Column)));

   --  Binary results: decode the types a page shows, and fall back to the raw bytes.
   function Text (From : Result_Reader; Column : Positive) return UTF8_String is
      Item : constant Postgres.Field := Current (From, Column);
      Kind : constant Type_Oid := Column_Type (From.Db.all, From.Result, Column);
   begin
      if From.Position = 0 or else Is_Null (Item) then
         return "";
      elsif From.Result.As_Text then
         return Postgres.Text (From.Db.all, Item);
      end if;
      case Kind is
         when Int2_Oid | Int4_Oid | Int8_Oid =>
            return UTF8_String (Encoding.Decimal_Image (Integer_Value (From.Db.all, Item)));
         when Bool_Oid =>
            return (if Boolean_Value (From.Db.all, Item) then "true" else "false");
         when Float4_Oid | Float8_Oid =>
            return UTF8_String (Float_Image (Float_Value (From.Db.all, Item)));
         when Timestamptz_Oid =>
            return UTF8_String (Times.Rfc3339 (Timestamp_Value (From.Db.all, Item)));
         when others =>
            return Postgres.Text (From.Db.all, Item);
      end case;
   end Text;

end Sparrow.Postgres.Queries;
