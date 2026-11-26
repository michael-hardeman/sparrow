package body Sparrow.Http.Requests with SPARK_Mode is

   use type Parser.Parse_Outcome;

   function Bytes (This : Request) return String is
     (if Buffers.Valid (This.Bytes) then Buffers.Content (This.Bytes) else "");

   function Loaded (This : Request) return Boolean is
     (This.Head.Outcome = Parser.Complete and then Parser.Consistent (This.Head, Bytes (This)));

   --  Source (Item) decoded, or "" when Item is not inside Source or its escapes are broken.
   function Decoded (Source : String; Item : Span; Plus_Is_Space : Boolean) return String is
      Into  : String (1 .. Length (Item));
      Last  : Natural;
      Valid : Boolean;
   begin
      if Length (Item) = 0 or else not Within (Item, Source) then
         return "";
      end if;
      Percent_Decode (Slice (Source, Item), Into, Last, Valid, Plus_Is_Space);
      return (if Valid then Into (1 .. Last) else "");
   end Decoded;

   function Verb (This : Request) return Method is (if Loaded (This) then This.Head.Verb else Other);

   function Path (This : Request) return String is (if Loaded (This) then Slice (Bytes (This), This.Head.Path) else "");

   function Query (This : Request) return String is
     (if Loaded (This) then Slice (Bytes (This), This.Head.Query) else "");

   function Header (This : Request; Name : String) return String is
     (if Loaded (This) then Slice (Bytes (This), Parser.Header_Value (Bytes (This), This.Head, Name)) else "");

   function Has_Header (This : Request; Name : String) return Boolean is
     (Loaded (This)
      and then (for some Index in 1 .. This.Head.Header_Total =>
                  Equal_Ignoring_Case (Slice (Bytes (This), This.Head.Headers (Index).Name), Name)));

   function Content (This : Request) return String is
     (if Loaded (This) and then Buffers.Valid (This.Bytes) and then This.Bytes.Data /= null
        and then This.Head.Head_Length < This.Bytes.Length
      then This.Bytes.Data (This.Head.Head_Length + 1 .. This.Bytes.Length)
      else "");

   function Parameter (This : Request; Name : String) return String is begin
      for Index in 1 .. This.Parameter_Total loop
         declare
            Item : constant Captured := This.Parameters (Index);
         begin
            if Item.Name (1 .. Item.Name_Length) = Name then
               return Decoded (Bytes (This), Item.Value, Plus_Is_Space => False);
            end if;
         end;
      end loop;
      return "";
   end Parameter;

   function Query_Value (This : Request; Name : String) return String is
      Source : constant String := Query (This);
   begin
      return Decoded (Source, Encoding.Query_Value (Source, Name), Plus_Is_Space => True);
   end Query_Value;

   --  Whether Name appears in Source (a=1&b) at all, with or without a value.
   function Names (Source : String; Name : String) return Boolean is
      First : Integer := Source'First;
   begin
      if Name'Length = 0 or else Source'Last = Integer'Last then
         return False;
      end if;
      while First <= Source'Last loop
         pragma Loop_Invariant (First >= Source'First);
         pragma Loop_Variant (Increases => First);
         declare
            Last : Natural := First;
         begin
            while Last <= Source'Last and then Source (Last) /= '&' loop
               pragma Loop_Invariant (Last >= First);
               pragma Loop_Variant (Increases => Last);
               Last := Last + 1;
            end loop;
            declare
               Equals : Natural := 0;   --  the item is Source (First .. Last - 1)
            begin
               for Position in First .. Last - 1 loop
                  if Source (Position) = '=' then
                     Equals := Position;
                     exit;
                  end if;
               end loop;
               if (if Equals = 0 then Source (First .. Last - 1) = Name else Source (First .. Equals - 1) = Name) then
                  return True;
               end if;
            end;
            exit when Last > Source'Last;
            First := Last + 1;
         end;
      end loop;
      return False;
   end Names;

   function Has_Query_Value (This : Request; Name : String) return Boolean is (Names (Query (This), Name));

   function Form_Value (This : Request; Name : String) return String is
      Source : constant String := Content (This);
   begin
      return Decoded (Source, Encoding.Query_Value (Source, Name), Plus_Is_Space => True);
   end Form_Value;

   function Has_Content_Type (This : Request; Media_Type : String) return Boolean is
      Value : constant String := Header (This, "Content-Type");
   begin
      for Index in Value'Range loop
         if Value (Index) in ';' | ' ' | ASCII.HT then
            return Equal_Ignoring_Case (Value (Value'First .. Index - 1), Media_Type);
         end if;
      end loop;
      return Equal_Ignoring_Case (Value, Media_Type);
   end Has_Content_Type;

   function Checked (Value : String; Default : UTF8_String) return UTF8_String is
     (if Valid_Utf8 (Value) then To_UTF8 (Value) else Default);

   function Parameter_Text (This : Request; Name : String; Default : UTF8_String := "") return UTF8_String is
     (Checked (Parameter (This, Name), Default));

   function Query_Text (This : Request; Name : String; Default : UTF8_String := "") return UTF8_String is
     (Checked (Query_Value (This, Name), Default));

   function Form_Text (This : Request; Name : String; Default : UTF8_String := "") return UTF8_String is
     (Checked (Form_Value (This, Name), Default));

   function Integer_Of (Value : String; Default : Long_Long_Integer) return Long_Long_Integer is
      Result : Long_Long_Integer;
      Valid  : Boolean;
   begin
      Parse_Decimal (Value, Result, Valid);
      return (if Valid then Result else Default);
   end Integer_Of;

   function Integer_Parameter (This : Request; Name : String; Default : Long_Long_Integer := 0)
      return Long_Long_Integer is (Integer_Of (Parameter (This, Name), Default));

   function Integer_Query (This : Request; Name : String; Default : Long_Long_Integer := 0)
      return Long_Long_Integer is (Integer_Of (Query_Value (This, Name), Default));

   --  "a=1; b=2": the value of Name, as sent (cookies are not percent-decoded by the protocol).
   function Cookie (This : Request; Name : String) return String is
      Source : constant String := Header (This, "Cookie");
      First  : Integer := Source'First;
   begin
      if Name'Length = 0 or else Source'Last = Integer'Last then
         return "";
      end if;
      while First <= Source'Last loop
         pragma Loop_Invariant (First >= Source'First);
         pragma Loop_Variant (Increases => First);
         while First <= Source'Last and then Source (First) = ' ' loop
            pragma Loop_Invariant (First >= First'Loop_Entry);
            pragma Loop_Variant (Increases => First);
            First := First + 1;
         end loop;
         exit when First > Source'Last;
         declare
            Last : Natural := First;
         begin
            while Last <= Source'Last and then Source (Last) /= ';' loop
               pragma Loop_Invariant (Last >= First);
               pragma Loop_Variant (Increases => Last);
               Last := Last + 1;
            end loop;
            if Last - First > Name'Length and then Source (First .. First + Name'Length - 1) = Name
              and then Source (First + Name'Length) = '='
            then
               declare
                  Value : constant String := Source (First + Name'Length + 1 .. Last - 1);
               begin
                  --  A value may be quoted (RFC 6265 4.1.1).
                  if Value'Length >= 2 and then Value (Value'First) = '"' and then Value (Value'Last) = '"' then
                     return Value (Value'First + 1 .. Value'Last - 1);
                  end if;
                  return Value;
               end;
            end if;
            exit when Last > Source'Last;
            First := Last + 1;
         end;
      end loop;
      return "";
   end Cookie;

   ----------
   -- Load --
   ----------

   procedure Load (This : in out Request; Bytes : in out Buffer; Valid : out Boolean) is begin
      Free (This);
      This.Bytes := Bytes;
      Bytes      := (Data => null, Length => 0, Overflowed => False);

      declare
         Head : constant Parser.Request_Head :=
           Parser.Parse_Head (Requests.Bytes (This), (Max_Head_Length     => Positive'Last / 2,
                                                       Max_Body_Length     => Natural'Last / 2,
                                                       Max_Streamed_Length => 0));
      begin
         Valid := Head.Outcome = Parser.Complete
           and then Head.Head_Length <= This.Bytes.Length
           and then (Head.Chunked
                     or else Head.Body_Length = Parser.Body_Size (This.Bytes.Length - Head.Head_Length));
         if Valid then
            This.Head := Head;
         end if;
      end;
   end Load;

   procedure Load_Head (This : in out Request; Bytes : in out Buffer; Valid : out Boolean) is begin
      Free (This);
      This.Bytes := Bytes;
      Bytes      := (Data => null, Length => 0, Overflowed => False);

      declare
         Head : constant Parser.Request_Head :=
           Parser.Parse_Head (Requests.Bytes (This), (Max_Head_Length     => Positive'Last / 2,
                                                       Max_Body_Length     => 0,
                                                       Max_Streamed_Length => Parser.Body_Size'Last));
      begin
         Valid := Head.Outcome = Parser.Complete and then Head.Head_Length = This.Bytes.Length;
         if Valid then
            This.Head     := Head;
            This.Streamed := True;
         end if;
      end;
   end Load_Head;

   procedure Set_Client_Address (This : in out Request; Address : String) is begin
      This.Client_Length := Address'Length;
      This.Client (1 .. Address'Length) := Address;
   end Set_Client_Address;

   procedure Set_Streamed (This : in out Request) is begin
      This.Streamed := True;
   end Set_Streamed;

   -------------------
   -- Add_Parameter --
   -------------------

   procedure Add_Parameter (This : in out Request; Name : String; Value : Span) is begin
      if This.Parameter_Total < Max_Parameters and then Name'Length <= Parameter_Name'Length then
         This.Parameter_Total := This.Parameter_Total + 1;
         This.Parameters (This.Parameter_Total) := (Name => [others => ' '], Name_Length => Name'Length,
                                                     Value => Value);
         This.Parameters (This.Parameter_Total).Name (1 .. Name'Length) := Name;
      end if;
   end Add_Parameter;

   function Path_First (This : Request) return Positive is
     (if This.Head.Outcome = Parser.Complete then This.Head.Path.First else 1);

   ----------
   -- Free --
   ----------

   procedure Set_Context (This : in out Request; To : Call_Context) is begin
      This.Called := To;
   end Set_Context;

   procedure Free (This : in out Request) is begin
      Buffers.Free (This.Bytes);
      This.Head            := (Outcome => Parser.Incomplete);
      This.Parameter_Total := 0;
      This.Streamed        := False;
   end Free;

   ---------------------------------------------------------------------------------------------------------------
   --  JSON bodies

   --  Every value but the top one sits in an array or object, which has one comma fewer than children: so
   --  1 + commas + brackets bounds the nodes (commas inside strings only add slack). Clamped to the largest
   --  document capacity; the decoded text is never longer than the source.
   function Node_Capacity_For (Source : String) return Json.Node_Count
     with Pre  => Source'First >= 1 and then Source'Last < Positive'Last,
          Post => Node_Capacity_For'Result in 1 .. Json.Node_Count'Last
   is
      Nodes : Long_Long_Integer := 1;
   begin
      for Index in Source'Range loop
         pragma Loop_Invariant (Nodes >= 1 and then Nodes <= Long_Long_Integer (Index - Source'First) + 1);
         if Source (Index) in ',' | '[' | '{' then
            Nodes := Nodes + 1;
         end if;
      end loop;
      return Json.Node_Count (Long_Long_Integer'Min (Nodes, Long_Long_Integer (Json.Node_Count'Last)));
   end Node_Capacity_For;

   function Json_Body (This : Request; Options : Json.Parse_Options := Json.Default_Options) return Json.Document
     with SPARK_Mode => Off
   is
      Source : constant String := Content (This);
   begin
      if Source'Length = 0 or else Source'Last = Positive'Last then
         return Result : Json.Document (Node_Capacity => 1, Text_Capacity => 1) do
            null;
         end return;
      end if;

      return Result : Json.Document
        (Node_Capacity => Node_Capacity_For (Source),
         Text_Capacity => Positive'Max (1, Source'Length))
      do
         declare
            Valid : Boolean;
         begin
            Json.Parse (Result, Source, Valid, Options);
         end;
      end return;
   end Json_Body;

end Sparrow.Http.Requests;
