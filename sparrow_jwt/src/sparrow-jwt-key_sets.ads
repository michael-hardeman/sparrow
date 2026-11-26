--  Tokens signed with a public key: RS256, ES256 and EdDSA, the algorithms identity providers and other services
--  sign with. The keys come as a JWKS (the JSON an identity provider publishes at its jwks_uri), or one by one.
--
--     Keys : constant Key_Sets.Key_Set := Key_Sets.Parse_Jwks (Client.Content (Answer));
--     ...
--     Key_Sets.Verify (Keys, Token, Now, Claims, Valid);
--
--  A token names its key (kid) and algorithm (alg) in its header. Verify takes the key of that name only, and
--  only when the algorithm is the one that key is for: an RSA key never checks an HS256 or ES256 signature, so a
--  token cannot choose a weaker check than its key (the "algorithm confusion" attacks). The time claims are
--  then checked as Sparrow.Jwt.Verify checks them.
with Sparrow.Crypto.Public_Keys; use Sparrow.Crypto.Public_Keys;
private with Ada.Containers.Vectors;
private with Ada.Strings.Unbounded;

package Sparrow.Jwt.Key_Sets with SPARK_Mode is

   Max_Signed_Token_Length : constant := 16_384;   --  RSA signatures and identity claims make tokens long

   type Key_Set is private;

   Empty_Set : constant Key_Set;

   function Count (Set : Key_Set) return Natural;

   function Has_Key (Set : Key_Set; Key_Id : String) return Boolean
     with Post => (if Has_Key'Result then Count (Set) > 0);

   --  The Index-th key of Set.
   function Key_At (Set : Key_Set; Index : Positive) return Public_Key
     with Pre  => Index <= Count (Set),
          Post => Is_Valid (Key_At'Result);

   Max_Jwks_Length : constant := 1_048_576;

   --  The keys of a JWKS that sign: RSA (2048 bits or more), EC P-256 and OKP Ed25519 keys, unless marked
   --  "use": "enc". Others (encryption keys, shared secrets, unknown kinds, weak or malformed keys) are left out,
   --  and an unreadable document gives Empty_Set.
   --  Global => null states that no program global is touched; the Document allocated by the Off body is local
   --  (dropping the aspect makes GNATprove generate an output __HEAP global and reject the function, E0005).
   function Parse_Jwks (Text : String) return Key_Set
     with Global => null,
          Post => (if Text'Length = 0 or else Text'Length > Max_Jwks_Length
                   then Parse_Jwks'Result = Empty_Set)
                  and then (for all Index in Positive range 1 .. Count (Parse_Jwks'Result) =>
                              Is_Valid (Key_At (Parse_Jwks'Result, Index)));

   --  Add Key under Key_Id ("" for a key that tokens do not name: then it must be the set's only key).
   procedure Add (Set : in out Key_Set; Key_Id : String; Key : Public_Key)
     with Pre  => Is_Valid (Key),
          Post => Count (Set) = Count (Set)'Old + 1 and then Has_Key (Set, Key_Id);

   Max_Header_Length : constant := 2_048;   --  a decoded header cannot exceed this

   --  The kid of Token's header, before anything is checked ("" when it has none): to tell a key the set does
   --  not have yet (fetch the JWKS again) from a bad token.
   function Key_Id_Of (Token : String) return String
     with Post => Key_Id_Of'Result'First = 1
                  and then Key_Id_Of'Result'Length <= Max_Header_Length
                  and then (if Token'Length > Max_Signed_Token_Length then Key_Id_Of'Result = "");

   --  Valid when Token is signed by its key in Keys with that key's algorithm, exp (required unless
   --  Require_Expiry is False) is after Now and nbf, if any, is not after Now. Claims then holds the payload.
   procedure Verify
     (Keys           : Key_Set;
      Token          : String;
      Now            : Unix_Seconds;
      Claims         : in out Json.Document;
      Valid          : out Boolean;
      Require_Expiry : Boolean := True)
     with Pre  => Claims.Text_Capacity < Positive'Last,
          Post => (if Valid then
                      Token'Length in 1 .. Max_Signed_Token_Length
                      and then (Has_Key (Keys, Key_Id_Of (Token)) or else Count (Keys) = 1)
                      and then Sparrow.Json.Is_Valid (Claims));

   --  A token carrying Claims (a JSON object's text), signed with Key, naming Key_Id in its header: for others
   --  to verify with the public key alone.
   function Sign (Key : Private_Key; Key_Id : String; Claims : UTF8_String) return String
     with Pre  => Is_Valid (Key) and then Key_Id'Length <= 256 and then Claims'Length <= 8192,
          Post => Sign'Result'First = 1 and then Sign'Result'Length >= 3;

   --  The algorithm a key of Kind signs with: "RS256", "ES256" or "EdDSA".
   function Algorithm_Of (Kind : Key_Kind) return String
     with Pre  => Kind /= None,
          Post => Algorithm_Of'Result =
                    (case Kind is
                        when Rsa     => "RS256",
                        when Ec_P256 => "ES256",
                        when Ed25519 => "EdDSA",
                        when None    => "");

private

   pragma SPARK_Mode (Off);   --  unbounded text and Ada.Containers.Vectors are not SPARK types

   use Ada.Strings.Unbounded;

   type Entry_Of_Set is record
      Key_Id    : Unbounded_String;
      Algorithm : Unbounded_String;   --  "" when the JWK did not say
      Key       : Public_Key;
   end record;

   package Entry_Vectors is new Ada.Containers.Vectors (Positive, Entry_Of_Set);

   type Key_Set is record
      Entries : Entry_Vectors.Vector;
   end record;

   Empty_Set : constant Key_Set := (Entries => Entry_Vectors.Empty_Vector);

end Sparrow.Jwt.Key_Sets;
