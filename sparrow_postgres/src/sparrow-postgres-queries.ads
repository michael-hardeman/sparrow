--  One call per query, and rows read by name: the everyday way to use a connection. The pipelined API in
--  Sparrow.Postgres stays underneath for throughput (many statements per round trip).
--
--     Find_User : aliased constant Postgres.Statement :=
--       Postgres.Define ("find_user", "select id, name from users where email = $1 limit $2");
--     ...
--     Queries.Query (Db, Find_User, [+Email, +Limit], Result);
--     for Row in Queries.Rows (Db, Result) loop
--        Show (Row.Integer_Value ("id"), Row.Text ("name"));
--     end loop;
--
--  Integer literals need a type to pick "+": +Long_Long_Integer'(5), or a typed constant.
with Ada.Iterator_Interfaces;
private with Ada.Strings.Unbounded;

package Sparrow.Postgres.Queries with SPARK_Mode => Off is

   ---------------------------------------------------------------------------------------------------------------
   --  Parameters

   type Parameter is private;
   type Parameter_List is array (Positive range <>) of Parameter;

   No_Parameter_Values : constant Parameter_List;

   function "+" (Value : UTF8_String) return Parameter;         --  text, varchar, json
   function "+" (Value : Long_Long_Integer) return Parameter;   --  int2, int4 or int8, as the statement takes
   function "+" (Value : Integer) return Parameter;
   function "+" (Value : Boolean) return Parameter;
   function "+" (Value : Long_Float) return Parameter;          --  float4 or float8
   function Bytes (Value : String) return Parameter;            --  bytea
   function Timestamp (Value : Unix_Microseconds) return Parameter;
   function Null_Value return Parameter;

   --  Bind Prepared with Parameters, run it and wait for its result: Result.Succeeded tells whether it worked
   --  (Result.State and Last_Failure say why not). The rows stay readable until the next query on This.
   --  Raises Connection_Error when the connection fails, or when Parameters do not fit the statement.
   procedure Query
     (This : in out Connection; Prepared : Statement; Parameters : Parameter_List; Result : out Statement_Result)
     with Global            => (In_Out => Sparrow.Postgres.Server),
          Exceptional_Cases => (Connection_Error => True),
          Post              => (if not Result.Succeeded then Result.Row_Count = 0
                                and then Result.Affected_Rows = 0);

   procedure Query (This : in out Connection; Prepared : Statement; Result : out Statement_Result)
     with Global            => (In_Out => Sparrow.Postgres.Server),
          Exceptional_Cases => (Connection_Error => True),
          Post              => (if not Result.Succeeded then Result.Row_Count = 0
                                and then Result.Affected_Rows = 0);

   ---------------------------------------------------------------------------------------------------------------
   --  Rows

   --  One row of a result. A column is named as the query names it (use AS for expressions) or numbered from
   --  1; an unknown name raises Constraint_Error. Values are total as in Sparrow.Postgres: a NULL reads as
   --  "", 0 or False.
   type Row is tagged private;

   function Number (This : Row) return Positive;

   function Field (This : Row; Column : String) return Postgres.Field;
   function Field (This : Row; Column : Positive) return Postgres.Field;

   function Is_Null (This : Row; Column : String) return Boolean
     with Post => Is_Null'Result = Sparrow.Postgres.Is_Null (Field (This, Column));
   function Text (This : Row; Column : String) return UTF8_String
     with Post => (if Is_Null (This, Column) then Text'Result = "");
   function Bytes (This : Row; Column : String) return String
     with Post => (if Is_Null (This, Column) then Bytes'Result = "");
   function Integer_Value (This : Row; Column : String) return Long_Long_Integer
     with Post => (if Is_Null (This, Column) then Integer_Value'Result = 0);
   function Boolean_Value (This : Row; Column : String) return Boolean
     with Post => (if Is_Null (This, Column) then not Boolean_Value'Result);
   function Float_Value (This : Row; Column : String) return Long_Float
     with Post => (if Is_Null (This, Column) then Float_Value'Result = 0.0);
   function Timestamp_Value (This : Row; Column : String) return Unix_Microseconds
     with Post => (if Is_Null (This, Column) then Timestamp_Value'Result = 0);

   function Is_Null (This : Row; Column : Positive) return Boolean
     with Post => Is_Null'Result = Sparrow.Postgres.Is_Null (Field (This, Column));
   function Text (This : Row; Column : Positive) return UTF8_String
     with Post => (if Is_Null (This, Column) then Text'Result = "");
   function Bytes (This : Row; Column : Positive) return String
     with Post => (if Is_Null (This, Column) then Bytes'Result = "");
   function Integer_Value (This : Row; Column : Positive) return Long_Long_Integer
     with Post => (if Is_Null (This, Column) then Integer_Value'Result = 0);
   function Boolean_Value (This : Row; Column : Positive) return Boolean
     with Post => (if Is_Null (This, Column) then not Boolean_Value'Result);
   function Float_Value (This : Row; Column : Positive) return Long_Float
     with Post => (if Is_Null (This, Column) then Float_Value'Result = 0.0);
   function Timestamp_Value (This : Row; Column : Positive) return Unix_Microseconds
     with Post => (if Is_Null (This, Column) then Timestamp_Value'Result = 0);

   function Has_Element (Position : Row) return Boolean;
   package Row_Iterators is new Ada.Iterator_Interfaces (Row, Has_Element);

   --  The rows of Result, in order, for "for Row in Rows (Db, Result) loop". This must outlive the loop.
   function Rows (This : Connection; Result : Statement_Result) return Row_Iterators.Forward_Iterator'Class;

   ---------------------------------------------------------------------------------------------------------------
   --  Rows read one at a time, as SQLite's are: what Sparrow.Templates.Bindings.Add_Rows takes.
   --
   --     procedure Add_Rows is new Sparrow.Templates.Bindings.Add_Rows (Queries.Result_Reader);
   --     ...
   --     Query (Db, List_Posts, [+Thread], Result);
   --     declare
   --        Posts : Queries.Result_Reader := Queries.Reader (Db, Result);
   --     begin
   --        Add_Rows (Data, "posts", Posts);
   --     end;

   type Result_Reader (<>) is limited private;

   function Column_Count (From : Result_Reader) return Natural;
   --  Whether From is on a row (false before the first and past the last).
   function On_Row (From : Result_Reader) return Boolean;

   --  Before the first row of Result. This must outlive the reader.
   function Reader (This : Connection; Result : Statement_Result) return Result_Reader
     with Post => not On_Row (Reader'Result) and then Column_Count (Reader'Result) = Result.Column_Count;

   function Next_Row (From : in out Result_Reader) return Boolean
     with Post => (if Next_Row'Result then On_Row (From));

   function Is_Null (From : Result_Reader; Column : Positive) return Boolean
     with Post => (if not On_Row (From) then Is_Null'Result);

   --  Any type, as text.
   function Text (From : Result_Reader; Column : Positive) return UTF8_String
     with Post => (if not On_Row (From) then Text'Result = "");

   function Column_Name (From : Result_Reader; Column : Positive) return String;

private

   type Parameter_Kind is (Text_Kind, Integer_Kind, Boolean_Kind, Float_Kind, Bytes_Kind, Timestamp_Kind,
                           Null_Kind);

   type Parameter is record
      Kind    : Parameter_Kind := Null_Kind;
      Content : Ada.Strings.Unbounded.Unbounded_String;   --  of text and bytes
      Whole   : Long_Long_Integer := 0;                    --  of integers and timestamps
      Flag    : Boolean := False;
      Real    : Long_Float := 0.0;
   end record;

   No_Parameter_Values : constant Parameter_List (1 .. 0) := [others => <>];

   type Connection_View is access constant Connection;

   type Row is tagged record
      Db       : Connection_View;
      Result   : Statement_Result;
      Position : Natural := 0;
   end record;

   type Result_Reader is limited record
      Db       : Connection_View;
      Result   : Statement_Result;
      Position : Natural := 0;   --  the current row; 0 before the first
   end record;

end Sparrow.Postgres.Queries;
