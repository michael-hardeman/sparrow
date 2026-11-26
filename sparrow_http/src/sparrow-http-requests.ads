--  A request as a handler sees it: the parsed head, the body, and what the router captured from the path.
--  A Request owns its bytes for as long as the handler runs, on whichever task that is.
--
--  Accessors are total: whatever is absent reads as "". They return bytes: what the client sent, unchecked.
with Sparrow.Buffers; use Sparrow.Buffers;
with Sparrow.Http.Parser;
with Sparrow.Encoding; use Sparrow.Encoding;
with Sparrow.Json;
with Sparrow.Times;

package Sparrow.Http.Requests with SPARK_Mode is

   type Request is limited private;

   function Verb (This : Request) return Method;

   --  The path as sent (still percent-encoded), without the query.
   function Path (This : Request) return String;

   --  The whole query string as sent, without the '?'.
   function Query (This : Request) return String;

   --  A header's value; the first one when it is repeated. Names are compared without case.
   function Header (This : Request; Name : String) return String;
   function Has_Header (This : Request; Name : String) return Boolean;

   --  Whether the Content-Type header names Media_Type ("application/json"), ignoring case and any parameters
   --  ("; charset=utf-8").
   function Has_Content_Type (This : Request; Media_Type : String) return Boolean;

   --  The body, as sent (a chunked body decoded). Parse it with Json_Body, or read a form with Form_Value.
   --  "" on a route with Body_Mode => Streamed: read the body with Sparrow.Http.Bodies instead.
   function Content (This : Request) return String;

   --  Whether the body is read as it arrives (Sparrow.Http.Bodies) rather than held in Content.
   function Body_Streamed (This : Request) return Boolean;

   --  The body parsed as JSON, into a document sized to it: nothing to choose, and no larger than the body
   --  needs. Check Json.Is_Valid before reading it.
   --
   --     Fields : constant Json.Document := Requests.Json_Body (Request);
   --     if not Json.Is_Valid (Fields) then
   --        Responses.Send (Response, Bad_Request, "the body is not JSON");
   --        return;
   --     end if;
   --  The document is sized to the body, so its discriminants cannot be fixed by SPARK (E0007); only that
   --  allocation is Off. The capacity scan is proved in a SPARK helper.
   function Json_Body (This : Request; Options : Json.Parse_Options := Json.Default_Options) return Json.Document
      with Post => (if Json.Is_Valid (Json_Body'Result) then Content (This)'Length > 0);

   --  What a route pattern's ":name" (or "*name") matched, percent-decoded.
   function Parameter (This : Request; Name : String) return String;

   --  A query string value, percent-decoded ('+' is a space).
   function Query_Value (This : Request; Name : String) return String;
   function Has_Query_Value (This : Request; Name : String) return Boolean;

   --  The same for an application/x-www-form-urlencoded body.
   function Form_Value (This : Request; Name : String) return String;

   --  A cookie of the Cookie header.
   function Cookie (This : Request; Name : String) return String;

   --  The same values checked into text: Default when absent or not well-formed UTF-8.
   function Parameter_Text (This : Request; Name : String; Default : UTF8_String := "") return UTF8_String;
   function Query_Text (This : Request; Name : String; Default : UTF8_String := "") return UTF8_String;
   function Form_Text (This : Request; Name : String; Default : UTF8_String := "") return UTF8_String;

   --  A path capture or query value read as a decimal integer: Default when absent or not one ("/items/:id"
   --  with database ids from 1 reads a malformed id as Default => 0, which no row has).
   function Integer_Parameter (This : Request; Name : String; Default : Long_Long_Integer := 0)
      return Long_Long_Integer;
   function Integer_Query (This : Request; Name : String; Default : Long_Long_Integer := 0)
      return Long_Long_Integer;

   --  Where and when the handler runs (Sparrow.Http.Call_Context), and its parts.
   function Context (This : Request) return Call_Context;
   function Worker (This : Request) return Worker_Count;            --  Reactor_Task, or the worker's number
   function Now (This : Request) return Sparrow.Times.Unix_Seconds;  --  read once, as the request arrived
   function Connection (This : Request) return Connection_Id;       --  to send to later: Sparrow.Http.Streams
   function Trace (This : Request) return Trace_Context;            --  see Sparrow.Http.Log

   --  The client's IP address as text: the connection's peer, or with Servers.Behind_Proxy the address the
   --  proxy names in X-Forwarded-For. "" outside a server.
   function Client_Address (This : Request) return String;

   ---------------------------------------------------------------------------------------------------------------
   --  For the server, and for tests that call handlers directly.

   procedure Set_Context (This : in out Request; To : Call_Context);

   Max_Parameters : constant := 8;

   --  Make This the request whose bytes are Bytes (head and body): This takes the buffer, Bytes is left empty.
   --  Valid is False when Bytes does not hold exactly one complete request; a chunked one comes decoded,
   --  every byte after the head being body.
   procedure Load (This : in out Request; Bytes : in out Buffer; Valid : out Boolean)
      with Pre => Sparrow.Buffers.Valid (Bytes);

   --  The same with only the head, for a request whose body is streamed.
   procedure Load_Head (This : in out Request; Bytes : in out Buffer; Valid : out Boolean)
      with Pre => Sparrow.Buffers.Valid (Bytes);

   --  Record the client's address (at most 45 characters: the longest IPv6 text).
   procedure Set_Client_Address (This : in out Request; Address : String)
      with Pre => Address'Length <= 45;

   --  Mark a request without a body as one whose (empty) body is streamed.
   procedure Set_Streamed (This : in out Request);
   --  Record a path capture; ignored past Max_Parameters or for a name longer than 32.
   procedure Add_Parameter (This : in out Request; Name : String; Value : Span);

   --  Where Path starts in the request's bytes (spans given to Add_Parameter are positions there).
   function Path_First (This : Request) return Positive;

   --  Whether This holds no storage.
   function Is_Empty (This : Request) return Boolean with Ghost;

   procedure Free (This : in out Request) with Post => Is_Empty (This);

private

   subtype Parameter_Name is String (1 .. 32);

   type Captured is record
      Name        : Parameter_Name := [others => ' '];
      Name_Length : Natural range 0 .. 32 := 0;
      Value       : Span;                     --  inside Bytes, still encoded
   end record;

   type Captured_List is array (1 .. Max_Parameters) of Captured;

   type Request is limited record
      Bytes           : Buffer;
      Head            : Parser.Request_Head;  --  Complete once loaded
      Parameters      : Captured_List;
      Parameter_Total : Natural range 0 .. Max_Parameters := 0;
      Called          : Call_Context;
      Streamed        : Boolean := False;
      Client          : String (1 .. 45) := [others => ' '];
      Client_Length   : Natural range 0 .. 45 := 0;
   end record;
   function Client_Address (This : Request) return String is (This.Client (1 .. This.Client_Length));
   function Body_Streamed (This : Request) return Boolean is (This.Streamed);

   function Context (This : Request) return Call_Context is (This.Called);
   function Worker (This : Request) return Worker_Count is (This.Called.Worker);
   function Now (This : Request) return Sparrow.Times.Unix_Seconds is (This.Called.Now);
   function Connection (This : Request) return Connection_Id is (This.Called.Connection);
   function Trace (This : Request) return Trace_Context is (This.Called.Trace);

   function Is_Empty (This : Request) return Boolean is (This.Bytes.Data = null);

end Sparrow.Http.Requests;
