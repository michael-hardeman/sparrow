--  Public-key signatures as JSON Web Tokens use them: RSA with SHA-256 (RS256, PKCS #1 v1.5), ECDSA on P-256 with
--  SHA-256 (ES256) and Ed25519 (EdDSA). Keys come from the parts a JWK carries, or from PEM.
--
--  A key is a reference to OpenSSL's: copying one is cheap, and a key may be used by several tasks at once.
--  Building a key from bad parts gives an invalid key, not an exception: check Is_Valid.
private with Ada.Finalization;
private with System;

package Sparrow.Crypto.Public_Keys with SPARK_Mode is

   type Key_Kind is
     (None,      --  an invalid key
      Rsa,       --  2048 bits or more; fewer are refused
      Ec_P256,
      Ed25519);

   ---------------------------------------------------------------------------------------------------------------
   --  Verifying

   type Public_Key is private;

   No_Public_Key : constant Public_Key;

   function Kind (Key : Public_Key) return Key_Kind;
   function Is_Valid (Key : Public_Key) return Boolean is (Kind (Key) /= None);

   --  From a JWK's parts, as bytes (big-endian numbers): RSA's n and e, P-256's x and y (32 bytes each),
   --  Ed25519's x (32 bytes). Bad lengths give No_Public_Key; a key of the matching kind otherwise.
   Max_Modulus_Bytes  : constant := 2048;
   Max_Exponent_Bytes : constant := 8;
   Coordinate_Bytes   : constant := 32;

   function Rsa_Key (Modulus, Exponent : String) return Public_Key
     with Post => (if Modulus'Length not in 1 .. Max_Modulus_Bytes
                     or else Exponent'Length not in 1 .. Max_Exponent_Bytes
                   then Rsa_Key'Result = No_Public_Key)
                  and then (if Is_Valid (Rsa_Key'Result) then Kind (Rsa_Key'Result) = Rsa);

   function Ec_P256_Key (X, Y : String) return Public_Key
     with Post => (if X'Length /= Coordinate_Bytes or else Y'Length /= Coordinate_Bytes
                   then Ec_P256_Key'Result = No_Public_Key)
                  and then (if Is_Valid (Ec_P256_Key'Result) then Kind (Ec_P256_Key'Result) = Ec_P256);

   function Ed25519_Key (X : String) return Public_Key
     with Post => (if X'Length /= Coordinate_Bytes then Ed25519_Key'Result = No_Public_Key)
                  and then (if Is_Valid (Ed25519_Key'Result) then Kind (Ed25519_Key'Result) = Ed25519);

   --  From PEM: "-----BEGIN PUBLIC KEY-----" (SubjectPublicKeyInfo) of any of the kinds above.
   Max_Pem_Length : constant := 1_000_000;

   function From_Pem (Text : String) return Public_Key
     with Post => (if Text'Length = 0 or else Text'Length > Max_Pem_Length
                   then From_Pem'Result = No_Public_Key);

   --  Whether Signed is Key's signature of Message: RSA's as it is, P-256's as the 64 bytes r then s (as in a
   --  JWS, not DER), Ed25519's 64 bytes. False for an invalid key.
   Signature_Bytes : constant := 64;

   function Verify (Key : Public_Key; Message : String; Signed : String) return Boolean
     with Post => (if not Is_Valid (Key) or else Signed'Length = 0
                     or else (Kind (Key) in Ec_P256 | Ed25519 and then Signed'Length /= Signature_Bytes)
                   then not Verify'Result);

   ---------------------------------------------------------------------------------------------------------------
   --  Signing, for tokens that others verify with the public key

   type Private_Key is private;

   function Kind (Key : Private_Key) return Key_Kind;
   function Is_Valid (Key : Private_Key) return Boolean is (Kind (Key) /= None);

   --  From PEM: "-----BEGIN PRIVATE KEY-----" (PKCS #8, unencrypted) of any of the kinds above.
   function Private_From_Pem (Text : String) return Private_Key
     with Post => (if Text'Length = 0 or else Text'Length > Max_Pem_Length
                   then not Is_Valid (Private_From_Pem'Result));

   --  From an Ed25519 seed (32 bytes, as Sparrow.Crypto.Signatures takes).
   function Ed25519_Private (Seed : String) return Private_Key
     with Post => (if Seed'Length /= Coordinate_Bytes then not Is_Valid (Ed25519_Private'Result))
                  and then (if Is_Valid (Ed25519_Private'Result)
                            then Kind (Ed25519_Private'Result) = Ed25519);

   function Public_Of (Key : Private_Key) return Public_Key
     with Pre  => Is_Valid (Key),
          Post => (if Is_Valid (Public_Of'Result) then Kind (Public_Of'Result) = Kind (Key));

   --  Key's signature of Message, in the form Verify takes. Crypto_Error when OpenSSL fails.
   Max_Rsa_Signature_Bytes : constant := 1024;   --  an 8192-bit RSA signature at most

   function Sign (Key : Private_Key; Message : String) return String
     with Pre  => Is_Valid (Key),
          Post => Sign'Result'First = 1
                  and then Sign'Result'Length <= (if Kind (Key) = Rsa then Max_Rsa_Signature_Bytes
                                                  else Signature_Bytes);

private

   pragma SPARK_Mode (Off);   --  a counted System.Address key handle held by a controlled type

   --  An EVP_PKEY, counted: Adjust takes a reference, Finalize gives one back.
   type Key_Reference is new Ada.Finalization.Controlled with record
      Handle : System.Address := System.Null_Address;
      Kind   : Key_Kind := None;
   end record;

   overriding procedure Adjust (This : in out Key_Reference);
   overriding procedure Finalize (This : in out Key_Reference);

   No_Reference : constant Key_Reference := (Ada.Finalization.Controlled with Handle => System.Null_Address,
                                             Kind => None);

   type Public_Key is record
      Reference : Key_Reference;
   end record;

   type Private_Key is record
      Reference : Key_Reference;
   end record;

   No_Public_Key : constant Public_Key :=
     (Reference => (Ada.Finalization.Controlled with Handle => System.Null_Address, Kind => None));

end Sparrow.Crypto.Public_Keys;
