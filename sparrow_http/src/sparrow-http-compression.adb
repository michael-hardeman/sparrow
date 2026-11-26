with Sparrow.Buffers; use Sparrow.Buffers;
with Sparrow.Encoding;
with Sparrow.Gzip;
with Sparrow.Http.Compression.Pool; use Sparrow.Http.Compression.Pool;

package body Sparrow.Http.Compression with SPARK_Mode is

   use type Responses.Response_Mode;

   function Lower (Item : Character) return Character is
     (if Item in 'A' .. 'Z' then Character'Val (Character'Pos (Item) + 32) else Item);

   --  Text (First .. Last) without blanks at either end, as bounds.
   procedure Trim (Text : String; First : in out Positive; Last : in out Natural)
      with Pre  => Text'Last < Positive'Last and then First >= Text'First and then Last <= Text'Last,
           Post => First >= First'Old and then Last <= Last'Old
                   and then (if First <= Last then First >= Text'First and then Last <= Text'Last)
   is
   begin
      while First <= Last and then Text (First) in ' ' | ASCII.HT loop
         pragma Loop_Invariant (First >= First'Loop_Entry and then First <= Last);
         pragma Loop_Variant (Increases => First);
         First := First + 1;
      end loop;
      while Last >= First and then Text (Last) in ' ' | ASCII.HT loop
         pragma Loop_Invariant (Last <= Last'Loop_Entry and then Last >= First);
         pragma Loop_Variant (Decreases => Last);
         Last := Last - 1;
      end loop;
   end Trim;

   --  Whether a q value is zero: "0", "0.", "0.0", "0.00" or "0.000".
   function Is_Zero (Text : String) return Boolean is
     (Text'Length in 1 .. 5 and then Text'Last < Positive'Last and then Text (Text'First) = '0'
      and then (Text'Length = 1
                or else (Text (Text'First + 1) = '.'
                         and then (for all Index in Text'First + 2 .. Text'Last => Text (Index) = '0'))));

   function Accepts_Gzip (Accept_Encoding : String) return Boolean is
      Gzip_Weight : Integer := -1;   --  -1: not listed; 0: refused; 1: taken
      Any_Weight  : Integer := -1;
      Start       : Positive;
   begin
      if Accept_Encoding'Length = 0 or else Accept_Encoding'Last = Positive'Last then
         return False;
      end if;
      Start := Accept_Encoding'First;
      while Start <= Accept_Encoding'Last loop
         pragma Loop_Invariant (Start >= Accept_Encoding'First);
         pragma Loop_Variant (Increases => Start);
         declare
            Stop      : Natural := Accept_Encoding'Last;
            Semicolon : Natural := 0;
         begin
            for Index in Start .. Accept_Encoding'Last loop
               if Accept_Encoding (Index) = ',' then
                  Stop := Index - 1;
                  exit;
               end if;
               pragma Loop_Invariant (Stop = Accept_Encoding'Last);
            end loop;
            for Index in Start .. Stop loop
               if Accept_Encoding (Index) = ';' then
                  Semicolon := Index;
                  exit;
               end if;
               pragma Loop_Invariant (Semicolon = 0);
            end loop;
            declare
               Name_First : Positive := Start;
               Name_Last  : Natural := (if Semicolon > 0 then Semicolon - 1 else Stop);
               Weight     : Integer := 1;
            begin
               Trim (Accept_Encoding, Name_First, Name_Last);
               --  Parameters: only q matters.
               if Semicolon > 0 then
                  declare
                     Item_First : Positive := Semicolon + 1;
                     Item_Last  : Natural := Stop;
                  begin
                     Trim (Accept_Encoding, Item_First, Item_Last);
                     if Item_Last - Item_First >= 1 and then Lower (Accept_Encoding (Item_First)) = 'q' then
                        declare
                           Value_First : Positive := Item_First + 1;
                           Value_Last  : Natural := Item_Last;
                        begin
                           Trim (Accept_Encoding, Value_First, Value_Last);
                           if Value_First <= Value_Last and then Accept_Encoding (Value_First) = '=' then
                              Value_First := Value_First + 1;
                              Trim (Accept_Encoding, Value_First, Value_Last);
                              if Value_First <= Value_Last
                                and then Is_Zero (Accept_Encoding (Value_First .. Value_Last))
                              then
                                 Weight := 0;
                              end if;
                           end if;
                        end;
                     end if;
                  end;
               end if;
               if Name_First <= Name_Last then
                  declare
                     Name : constant String := Accept_Encoding (Name_First .. Name_Last);
                  begin
                     if Encoding.Equal_Ignoring_Case (Name, "gzip")
                       or else Encoding.Equal_Ignoring_Case (Name, "x-gzip")
                     then
                        Gzip_Weight := Weight;
                     elsif Name = "*" then
                        Any_Weight := Weight;
                     end if;
                  end;
               end if;
            end;
            exit when Stop >= Accept_Encoding'Last - 1;
            Start := Stop + 2;
         end;
      end loop;
      return (if Gzip_Weight >= 0 then Gzip_Weight > 0 else Any_Weight > 0);
   end Accepts_Gzip;

   function Compressible (Media_Type : String) return Boolean is
      First : Positive;
      Last  : Natural;
   begin
      if Media_Type'Length = 0 or else Media_Type'Last = Positive'Last then
         return False;
      end if;
      First := Media_Type'First;
      Last  := Media_Type'Last;
      for Index in Media_Type'Range loop
         if Media_Type (Index) = ';' then
            Last := Index - 1;
            exit;
         end if;
         pragma Loop_Invariant (Last = Media_Type'Last);
      end loop;
      Trim (Media_Type, First, Last);
      if First > Last then
         return False;
      end if;
      declare
         Kind : constant String := Media_Type (First .. Last);

         function Named (Name : String) return Boolean is (Encoding.Equal_Ignoring_Case (Kind, Name));

         function Ends_With (Suffix : String) return Boolean is
           (Kind'Length > Suffix'Length and then Kind'Last < Positive'Last
            and then Encoding.Equal_Ignoring_Case (Kind (Kind'Last - Suffix'Length + 1 .. Kind'Last), Suffix));
      begin
         return (Kind'Length > 5 and then Encoding.Equal_Ignoring_Case (Kind (Kind'First .. Kind'First + 4), "text/")
                 and then not Named ("text/event-stream"))
           or else Named ("application/json") or else Named ("application/javascript")
           or else Named ("application/x-javascript") or else Named ("application/xml")
           or else Named ("application/wasm") or else Named ("image/svg+xml") or else Named ("image/x-icon")
           or else Named ("font/ttf") or else Named ("font/otf")
           or else Ends_With ("+json") or else Ends_With ("+xml");
      end;
   end Compressible;

   function Contains_Folded (Text, Part : String) return Boolean is
   begin
      --  An empty part matches everywhere; the bound below would overflow at Text'Last = Integer'Last.
      if Part'Length = 0 then
         return True;
      end if;
      if Part'Length > Text'Length then
         return False;
      end if;
      for Start in Text'First .. Text'Last - Part'Length + 1 loop
         if Encoding.Equal_Ignoring_Case (Text (Start .. Start + (Part'Length - 1)), Part) then
            return True;
         end if;
      end loop;
      return False;
   end Contains_Folded;

   function Compressible_Response (Response : Responses.Response) return Boolean is
     (Response.Mode = Responses.Whole
      and then Response.Status in 200 .. 299
      and then Response.Status not in No_Content | Partial_Content
      and then Response.Content.Length >= Minimum_Length
      and then Compressible (Responses.Header (Response, "Content-Type"))
      and then Responses.Header (Response, "Content-Encoding") = ""
      and then not Contains_Folded (Responses.Header (Response, "Cache-Control"), "no-transform"));

   function Eligible (Request : Requests.Request; Response : Responses.Response) return Boolean is
     (Compressible_Response (Response)
      and then Accepts_Gzip (Requests.Header (Request, "Accept-Encoding")));

   procedure Apply (Request : Requests.Request; Response : in out Responses.Response) with SPARK_Mode => Off is
      Length : constant Natural := Response.Content.Length;
   begin
      --  The cheap response tests first: most responses stop here. Vary is added before the client is checked
      --  so that a plain response is still marked as varying on Accept-Encoding.
      if not Compressible_Response (Response) then
         return;
      end if;

      declare
         Vary : constant String := Responses.Header (Response, "Vary");
      begin
         if Vary = "" then
            Responses.Set_Header (Response, "Vary", "Accept-Encoding");
         elsif Vary /= "*" and then not Contains_Folded (Vary, "accept-encoding") then
            Responses.Remove_Header (Response, "Vary");
            Responses.Set_Header (Response, "Vary", Vary & ", Accept-Encoding");
         end if;
      end;
      if not Accepts_Gzip (Requests.Header (Request, "Accept-Encoding")) then
         return;
      end if;

      declare
         Item    : Compressor_Access;
         Last    : Natural;
         Fits    : Boolean;
         Padding : Natural;
      begin
         Take (Item);
         if Item.Output = null or else Item.Output'Length < Length then
            Free (Item.Output);
            Item.Output := new String (1 .. Length);
         end if;
         --  Room for one byte less than the original: a result that is not smaller is not used.
         Draw_Padding (Item.all, Padding);
         Gzip.Compress (Item.Work, Response.Content.Data (1 .. Length), Item.Output (1 .. Length - 1), Last, Fits,
                        Padding);
         if Fits then
            Clear (Response.Content);
            Append (Response.Content, Item.Output (1 .. Last));
            Responses.Set_Header (Response, "Content-Encoding", "gzip");
            declare
               Tag : constant String := Responses.Header (Response, "ETag");
            begin
               if Tag'Length > 0 and then Tag (Tag'First) = '"' then
                  Responses.Remove_Header (Response, "ETag");
                  Responses.Set_Header (Response, "ETag", "W/" & Tag);
               end if;
            end;
         end if;
         Give (Item);
      exception
         when others =>
            Discard (Item);
            raise;
      end;
   end Apply;

end Sparrow.Http.Compression;
