with Ada.Unchecked_Deallocation;
with Sparrow.Base64; use Sparrow.Base64;
with Sparrow.Buffers;
with Sparrow.Json.Writers;

package body Sparrow.Jwt.Key_Sets with SPARK_Mode => Off is

   use Sparrow.Json;
   package Signing renames Sparrow.Crypto.Public_Keys;

   type Document_Access is access Document;
   procedure Free is new Ada.Unchecked_Deallocation (Document, Document_Access);

   function Algorithm_Of (Kind : Key_Kind) return String is
     (case Kind is
         when Rsa     => "RS256",
         when Ec_P256 => "ES256",
         when Ed25519 => "EdDSA",
         when None    => "");

   --  The bytes of base64url Text; Valid is False when it is not base64url.
   procedure Decode_Url (Text : String; Into : out Buffers.Buffer; Valid : out Boolean) is
      Decoded : String (1 .. Decoded_Length (Text'Length));
      Last    : Natural;
   begin
      Decode (Text, Decoded, Last, Valid, Url_Safe);
      if Valid then
         Buffers.Append (Into, Decoded (1 .. Last));
      end if;
   end Decode_Url;

   --  The bytes of the base64url member Name of the object Item; "" when absent or not base64url.
   function Bytes_Of (Doc : Document; Item : Node_Count; Name : String) return String is
      Node   : constant Node_Count := Member (Doc, Item, UTF8_String (Name));
      Into   : Buffers.Buffer;
      Valid  : Boolean;
   begin
      if Kind_Of (Doc, Node) /= String_Kind then
         return "";
      end if;
      Decode_Url (String (Value (Doc, Node)), Into, Valid);
      return Result : constant String := (if Valid then Buffers.Content (Into) else "") do
         Buffers.Free (Into);
      end return;
   end Bytes_Of;

   function Parse_Jwks (Text : String) return Key_Set is
      Result : Key_Set;
      Doc    : Document_Access;
      Parsed : Boolean;
   begin
      if Text'Length = 0 or else Text'Length > Max_Jwks_Length then
         return Empty_Set;
      end if;
      Doc := new Document (Node_Capacity => Node_Index (Natural'Min (Text'Length, 100_000)),
                           Text_Capacity => Text'Length);
      declare
         Source : constant String (1 .. Text'Length) := Text;
      begin
         Parse (Doc.all, Source, Parsed);
      end;
      if Parsed then
         declare
            Keys : constant Node_Count := Member (Doc.all, Root, "keys");
            Item : Node_Count :=
              (if Kind_Of (Doc.all, Keys) = Array_Kind then First_Child (Doc.all, Keys) else No_Node);
         begin
            while Item /= No_Node loop
               declare
                  function Field (Name : String) return String is
                    (String (Json.Text (Doc.all, UTF8_String (Name), From => Item)));
                  Key_Type : constant String := Field ("kty");
                  Curve    : constant String := Field ("crv");
                  Key      : Public_Key := No_Public_Key;
               begin
                  if Field ("use") in "" | "sig" then
                     if Key_Type = "RSA" then
                        Key := Rsa_Key (Bytes_Of (Doc.all, Item, "n"), Bytes_Of (Doc.all, Item, "e"));
                     elsif Key_Type = "EC" and then Curve = "P-256" then
                        Key := Ec_P256_Key (Bytes_Of (Doc.all, Item, "x"), Bytes_Of (Doc.all, Item, "y"));
                     elsif Key_Type = "OKP" and then Curve = "Ed25519" then
                        Key := Ed25519_Key (Bytes_Of (Doc.all, Item, "x"));
                     end if;
                  end if;
                  if Is_Valid (Key)
                    and then Field ("alg") in "" | Algorithm_Of (Signing.Kind (Key))   --  as the JWK says, if it does
                  then
                     Result.Entries.Append
                       (Entry_Of_Set'(Key_Id    => To_Unbounded_String (Field ("kid")),
                         Algorithm => To_Unbounded_String (Field ("alg")),
                         Key       => Key));
                  end if;
               end;
               Item := Next_Sibling (Doc.all, Item);
            end loop;
         end;
      end if;
      Free (Doc);
      return Result;
   end Parse_Jwks;

   procedure Add (Set : in out Key_Set; Key_Id : String; Key : Public_Key) is
   begin
      Set.Entries.Append
        (Entry_Of_Set'(Key_Id => To_Unbounded_String (Key_Id), Algorithm => Null_Unbounded_String, Key => Key));
   end Add;

   function Count (Set : Key_Set) return Natural is (Natural (Set.Entries.Length));

   function Key_At (Set : Key_Set; Index : Positive) return Public_Key is (Set.Entries (Index).Key);

   function Has_Key (Set : Key_Set; Key_Id : String) return Boolean is
     (for some Item of Set.Entries => Item.Key_Id = Key_Id);

   --  The positions of Token's two dots; both 0 unless it has exactly two.
   procedure Find_Dots (Token : String; First_Dot, Second_Dot : out Natural) is
   begin
      First_Dot  := 0;
      Second_Dot := 0;
      for Position in Token'Range loop
         if Token (Position) = '.' then
            if First_Dot = 0 then
               First_Dot := Position;
            elsif Second_Dot = 0 then
               Second_Dot := Position;
            else
               First_Dot  := 0;
               Second_Dot := 0;
               return;
            end if;
         end if;
      end loop;
      if Second_Dot = 0 then
         First_Dot := 0;
      end if;
   end Find_Dots;

   --  alg and kid of Token's header; Valid is False when the header is not a JSON object.
   procedure Read_Header (Token : String; Algorithm, Key_Id : out Unbounded_String; Valid : out Boolean) is
      First_Dot, Second_Dot : Natural;
      Header                : Buffers.Buffer;
   begin
      Algorithm := Null_Unbounded_String;
      Key_Id    := Null_Unbounded_String;
      Valid     := False;
      if Token'Length > Max_Signed_Token_Length then
         return;
      end if;
      Find_Dots (Token, First_Dot, Second_Dot);
      if First_Dot = 0 then
         return;
      end if;
      Decode_Url (Token (Token'First .. First_Dot - 1), Header, Valid);
      if Valid and then Header.Length in 1 .. Max_Header_Length then
         declare
            Doc    : Document (Node_Capacity => 64, Text_Capacity => Max_Header_Length);
            Source : constant String (1 .. Header.Length) := Buffers.Content (Header);
         begin
            Parse (Doc, Source, Valid);
            Valid := Valid and then Kind_Of (Doc, Root) = Object_Kind;
            if Valid then
               Algorithm := To_Unbounded_String (String (Text (Doc, "alg")));
               Key_Id    := To_Unbounded_String (String (Text (Doc, "kid")));
            end if;
         end;
      else
         Valid := False;
      end if;
      Buffers.Free (Header);
   end Read_Header;

   function Key_Id_Of (Token : String) return String is
      Algorithm, Key_Id : Unbounded_String;
      Valid             : Boolean;
   begin
      Read_Header (Token, Algorithm, Key_Id, Valid);
      return To_String (Key_Id);
   end Key_Id_Of;

   procedure Verify
     (Keys           : Key_Set;
      Token          : String;
      Now            : Unix_Seconds;
      Claims         : in out Json.Document;
      Valid          : out Boolean;
      Require_Expiry : Boolean := True)
   is
      Algorithm, Key_Id     : Unbounded_String;
      First_Dot, Second_Dot : Natural;
      Chosen                : Natural := 0;   --  the entry of the token's key
   begin
      Valid := False;
      Read_Header (Token, Algorithm, Key_Id, Valid);
      if not Valid then
         return;
      end if;
      Valid := False;

      for Index in Keys.Entries.First_Index .. Keys.Entries.Last_Index loop
         if Keys.Entries (Index).Key_Id = Key_Id then
            Chosen := Index;
            exit;
         end if;
      end loop;
      if Chosen = 0 and then Key_Id = "" and then Count (Keys) = 1 then   --  a set of one key, a token naming none
         Chosen := Keys.Entries.First_Index;
      end if;
      if Chosen = 0 then
         return;
      end if;

      declare
         Item : Entry_Of_Set renames Keys.Entries (Chosen);
      begin
         --  The key decides the algorithm: the token's alg must be the one its key signs with.
         if To_String (Algorithm) /= Algorithm_Of (Signing.Kind (Item.Key))
           or else (Item.Algorithm /= "" and then Item.Algorithm /= Algorithm)
         then
            return;
         end if;
         Find_Dots (Token, First_Dot, Second_Dot);
         declare
            Signature : Buffers.Buffer;
            Decoded   : Boolean;
            Signed    : Boolean;
         begin
            Decode_Url (Token (Second_Dot + 1 .. Token'Last), Signature, Decoded);
            Signed := Decoded
              and then Signing.Verify (Item.Key, Token (Token'First .. Second_Dot - 1),
                                           Buffers.Content (Signature));
            Buffers.Free (Signature);
            if not Signed then
               return;
            end if;
         end;
      end;

      declare
         Own : constant String (1 .. Token'Length) := Token;
      begin
         Check_Signed (Own, First_Dot - Token'First + 1, Second_Dot - Token'First + 1, To_String (Algorithm), Now,
                       Claims, Valid, Require_Expiry);
      end;
   end Verify;

   function Sign (Key : Private_Key; Key_Id : String; Claims : UTF8_String) return String is
      Header : Buffers.Buffer;
   begin
      Buffers.Append (Header, "{""alg"":""" & Algorithm_Of (Signing.Kind (Key)) & """,""kid"":");
      Json.Writers.Append_String (Header, UTF8_String (Key_Id));
      Buffers.Append (Header, ",""typ"":""JWT""}");
      declare
         Signed : constant String :=
           Encode (Buffers.Content (Header), Url_Safe) & "." & Encode (String (Claims), Url_Safe);
      begin
         Buffers.Free (Header);
         return Signed & "." & Encode (Signing.Sign (Key, Signed), Url_Safe);
      end;
   end Sign;

end Sparrow.Jwt.Key_Sets;
