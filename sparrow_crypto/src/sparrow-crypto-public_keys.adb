with Interfaces.C; use Interfaces.C;
with Sparrow.Crypto.Libcrypto; use Sparrow.Crypto.Libcrypto;
with System; use System;

package body Sparrow.Crypto.Public_Keys with SPARK_Mode => Off is

   EVP_PKEY_RSA     : constant := 6;
   EVP_PKEY_EC      : constant := 408;
   EVP_PKEY_ED25519 : constant := 1087;
   EVP_PKEY_PUBLIC_KEY : constant := 16#86#;   --  the public key and its domain parameters

   Minimum_Rsa_Bits : constant := 2048;

   function EVP_PKEY_CTX_new_from_name (Library : Address; Name : char_array; Properties : Address) return Address
      with Import, Convention => C, External_Name => "EVP_PKEY_CTX_new_from_name";
   procedure EVP_PKEY_CTX_free (Context : Address)
      with Import, Convention => C, External_Name => "EVP_PKEY_CTX_free";
   function EVP_PKEY_fromdata_init (Context : Address) return int
      with Import, Convention => C, External_Name => "EVP_PKEY_fromdata_init";
   function EVP_PKEY_fromdata
     (Context : Address; Key : access Address; Selection : int; Parameters : Address) return int
      with Import, Convention => C, External_Name => "EVP_PKEY_fromdata";
   function EVP_PKEY_new_raw_public_key (Kind : int; Engine : Address; Key : Address; Length : size_t)
      return Address
      with Import, Convention => C, External_Name => "EVP_PKEY_new_raw_public_key";
   function EVP_PKEY_new_raw_private_key (Kind : int; Engine : Address; Key : Address; Length : size_t)
      return Address
      with Import, Convention => C, External_Name => "EVP_PKEY_new_raw_private_key";
   function EVP_PKEY_up_ref (Key : Address) return int
      with Import, Convention => C, External_Name => "EVP_PKEY_up_ref";
   procedure EVP_PKEY_free (Key : Address) with Import, Convention => C, External_Name => "EVP_PKEY_free";
   function EVP_PKEY_get_id (Key : Address) return int
      with Import, Convention => C, External_Name => "EVP_PKEY_get_id";
   function EVP_PKEY_get_bits (Key : Address) return int
      with Import, Convention => C, External_Name => "EVP_PKEY_get_bits";
   function EVP_PKEY_get_utf8_string_param
     (Key : Address; Name : char_array; Into : Address; Size : size_t; Length : access size_t) return int
      with Import, Convention => C, External_Name => "EVP_PKEY_get_utf8_string_param";
   function EVP_sha256 return Address with Import, Convention => C, External_Name => "EVP_sha256";
   function EVP_DigestSignInit
     (Context : Address; Key_Context : Address; Kind : Address; Engine : Address; Key : Address) return int
      with Import, Convention => C, External_Name => "EVP_DigestSignInit";
   function EVP_DigestSign
     (Context : Address; Into : Address; Length : access size_t; Data : Address; Count : size_t) return int
      with Import, Convention => C, External_Name => "EVP_DigestSign";
   function EVP_DigestVerifyInit
     (Context : Address; Key_Context : Address; Kind : Address; Engine : Address; Key : Address) return int
      with Import, Convention => C, External_Name => "EVP_DigestVerifyInit";
   function EVP_DigestVerify
     (Context : Address; Signed : Address; Signed_Length : size_t; Data : Address; Count : size_t) return int
      with Import, Convention => C, External_Name => "EVP_DigestVerify";

   function BIO_new_mem_buf (Data : Address; Length : int) return Address
      with Import, Convention => C, External_Name => "BIO_new_mem_buf";
   function BIO_free (Bio : Address) return int with Import, Convention => C, External_Name => "BIO_free";
   function PEM_read_bio_PUBKEY (Bio : Address; Into, Callback, User : Address) return Address
      with Import, Convention => C, External_Name => "PEM_read_bio_PUBKEY";
   function PEM_read_bio_PrivateKey (Bio : Address; Into, Callback, User : Address) return Address
      with Import, Convention => C, External_Name => "PEM_read_bio_PrivateKey";

   function BN_bin2bn (Data : Address; Length : int; Into : Address) return Address
      with Import, Convention => C, External_Name => "BN_bin2bn";
   procedure BN_free (Number : Address) with Import, Convention => C, External_Name => "BN_free";
   function BN_bn2binpad (Number : Address; Into : Address; Length : int) return int
      with Import, Convention => C, External_Name => "BN_bn2binpad";
   function ECDSA_SIG_new return Address with Import, Convention => C, External_Name => "ECDSA_SIG_new";
   procedure ECDSA_SIG_free (Signature : Address)
      with Import, Convention => C, External_Name => "ECDSA_SIG_free";
   function ECDSA_SIG_set0 (Signature, R, S : Address) return int
      with Import, Convention => C, External_Name => "ECDSA_SIG_set0";
   function ECDSA_SIG_get0_r (Signature : Address) return Address
      with Import, Convention => C, External_Name => "ECDSA_SIG_get0_r";
   function ECDSA_SIG_get0_s (Signature : Address) return Address
      with Import, Convention => C, External_Name => "ECDSA_SIG_get0_s";
   function i2d_ECDSA_SIG (Signature : Address; Into : access Address) return int
      with Import, Convention => C, External_Name => "i2d_ECDSA_SIG";
   function d2i_ECDSA_SIG (Into : Address; From : access Address; Length : long) return Address
      with Import, Convention => C, External_Name => "d2i_ECDSA_SIG";

   ---------------------------------------------------------------------------------------------------------------
   --  References

   overriding procedure Adjust (This : in out Key_Reference) is
   begin
      if This.Handle /= Null_Address and then EVP_PKEY_up_ref (This.Handle) /= 1 then
         This.Handle := Null_Address;
         This.Kind   := None;
      end if;
   end Adjust;

   overriding procedure Finalize (This : in out Key_Reference) is
   begin
      if This.Handle /= Null_Address then
         EVP_PKEY_free (This.Handle);
         This.Handle := Null_Address;
         This.Kind   := None;
      end if;
   end Finalize;

   function Kind (Key : Public_Key) return Key_Kind is (Key.Reference.Kind);
   function Kind (Key : Private_Key) return Key_Kind is (Key.Reference.Kind);

   --  What Handle is, when it is one of the kinds taken; None (and Handle freed) otherwise.
   function Kind_Of (Handle : Address) return Key_Kind is
      Result : Key_Kind := None;
   begin
      if Handle = Null_Address then
         Clear_Errors;
         return None;
      end if;
      case EVP_PKEY_get_id (Handle) is
         when EVP_PKEY_RSA =>
            if EVP_PKEY_get_bits (Handle) >= Minimum_Rsa_Bits then
               Result := Rsa;
            end if;
         when EVP_PKEY_EC =>
            declare
               Group  : aliased char_array (1 .. 32) := [others => nul];
               Length : aliased size_t := 0;
            begin
               if EVP_PKEY_get_utf8_string_param (Handle, To_C ("group"), Group'Address, Group'Length,
                                                  Length'Access) = 1
                 and then To_Ada (Group) in "prime256v1" | "P-256"
               then
                  Result := Ec_P256;
               end if;
            end;
         when EVP_PKEY_ED25519 =>
            Result := Ed25519;
         when others =>
            null;
      end case;
      if Result = None then
         EVP_PKEY_free (Handle);
         Clear_Errors;
      end if;
      return Result;
   end Kind_Of;

   function Public_From (Handle : Address) return Public_Key is
      Found : constant Key_Kind := Kind_Of (Handle);
   begin
      if Found = None then
         return No_Public_Key;
      end if;
      return (Reference => (Ada.Finalization.Controlled with Handle => Handle, Kind => Found));
   end Public_From;

   function Private_From (Handle : Address) return Private_Key is
      Found : constant Key_Kind := Kind_Of (Handle);
   begin
      if Found = None then
         return (Reference => No_Reference);
      end if;
      return (Reference => (Ada.Finalization.Controlled with Handle => Handle, Kind => Found));
   end Private_From;

   --  A key of the algorithm Name (NUL-terminated in C) from Parameters.
   function From_Data (Name : String; Parameters : Parameter_List) return Address is
      Context : constant Address := EVP_PKEY_CTX_new_from_name (Null_Address, To_C (Name), Null_Address);
      Result  : aliased Address := Null_Address;
   begin
      if Context /= Null_Address then
         if EVP_PKEY_fromdata_init (Context) /= 1
           or else EVP_PKEY_fromdata (Context, Result'Access, EVP_PKEY_PUBLIC_KEY, Parameters'Address) /= 1
         then
            Result := Null_Address;
         end if;
         EVP_PKEY_CTX_free (Context);
      end if;
      return Result;
   end From_Data;

   --  Number (big-endian, as a JWK has it) in the machine's order, as OSSL_PARAM integers are.
   function Native_Order (Number : String) return String is
      Result : String (1 .. Number'Length);
   begin
      if System."=" (System.Default_Bit_Order, System.High_Order_First) then
         Result := Number;
      else
         for Index in Result'Range loop
            Result (Index) := Number (Number'Last - (Index - 1));
         end loop;
      end if;
      return Result;
   end Native_Order;

   function Rsa_Key (Modulus, Exponent : String) return Public_Key is
      N_Name : aliased constant char_array := To_C ("n");
      E_Name : aliased constant char_array := To_C ("e");
      N      : aliased String := Native_Order (Modulus);
      E      : aliased String := Native_Order (Exponent);
   begin
      if Modulus'Length not in 1 .. Max_Modulus_Bytes
        or else Exponent'Length not in 1 .. Max_Exponent_Bytes
      then
         return No_Public_Key;
      end if;
      return Public_From
        (From_Data ("RSA",
                    [(Key => N_Name'Address, Data_Type => OSSL_PARAM_UNSIGNED_INTEGER, Data => N'Address,
                      Data_Size => N'Length, others => <>),
                     (Key => E_Name'Address, Data_Type => OSSL_PARAM_UNSIGNED_INTEGER, Data => E'Address,
                      Data_Size => E'Length, others => <>),
                     (others => <>)]));
   end Rsa_Key;

   function Ec_P256_Key (X, Y : String) return Public_Key is
      Group_Name : aliased constant char_array := To_C ("group");
      Point_Name : aliased constant char_array := To_C ("pub");
      Group      : aliased constant char_array := To_C ("P-256");
      Point      : aliased constant String := Character'Val (4) & X & Y;   --  uncompressed
   begin
      if X'Length /= Coordinate_Bytes or else Y'Length /= Coordinate_Bytes then
         return No_Public_Key;
      end if;
      return Public_From
        (From_Data ("EC",
                    [(Key => Group_Name'Address, Data_Type => OSSL_PARAM_UTF8_STRING, Data => Group'Address,
                      Data_Size => Group'Length - 1, others => <>),
                     (Key => Point_Name'Address, Data_Type => OSSL_PARAM_OCTET_STRING, Data => Point'Address,
                      Data_Size => Point'Length, others => <>),
                     (others => <>)]));
   end Ec_P256_Key;

   function Ed25519_Key (X : String) return Public_Key is
   begin
      if X'Length /= Coordinate_Bytes then
         return No_Public_Key;
      end if;
      return Public_From
        (EVP_PKEY_new_raw_public_key (EVP_PKEY_ED25519, Null_Address, Start_Of (X), Coordinate_Bytes));
   end Ed25519_Key;

   type Pem_Reader is access function (Bio : Address; Into, Callback, User : Address) return Address
      with Convention => C;

   --  A PEM key of Text, read by Reader.
   function Read_Pem (Text : String; Reader : Pem_Reader) return Address
   is
      Bio    : Address;
      Result : Address := Null_Address;
   begin
      if Text'Length = 0 or else Text'Length > Max_Pem_Length then
         return Null_Address;
      end if;
      Bio := BIO_new_mem_buf (Start_Of (Text), int (Text'Length));
      if Bio /= Null_Address then
         Result := Reader (Bio, Null_Address, Null_Address, Null_Address);
         if BIO_free (Bio) /= 1 then
            null;
         end if;
      end if;
      return Result;
   end Read_Pem;

   function From_Pem (Text : String) return Public_Key is
     (Public_From (Read_Pem (Text, PEM_read_bio_PUBKEY'Access)));

   function Private_From_Pem (Text : String) return Private_Key is
     (Private_From (Read_Pem (Text, PEM_read_bio_PrivateKey'Access)));

   function Ed25519_Private (Seed : String) return Private_Key is
   begin
      if Seed'Length /= Coordinate_Bytes then
         return (Reference => No_Reference);
      end if;
      return Private_From
        (EVP_PKEY_new_raw_private_key (EVP_PKEY_ED25519, Null_Address, Start_Of (Seed), Coordinate_Bytes));
   end Ed25519_Private;

   function Public_Of (Key : Private_Key) return Public_Key is
   begin
      return (Reference => Key.Reference);   --  Adjust takes a reference
   end Public_Of;

   ---------------------------------------------------------------------------------------------------------------
   --  ECDSA signatures: r then s, 32 bytes each, in a JWS; DER for OpenSSL

   function Der_Of (Raw : String) return String is
      Signature : constant Address := ECDSA_SIG_new;
      R, S      : Address;
   begin
      if Signature = Null_Address then
         Fail ("ECDSA_SIG_new");
      end if;
      R := BN_bin2bn (Start_Of (Raw), 32, Null_Address);
      S := BN_bin2bn (Start_Of (Raw (Raw'First + 32 .. Raw'Last)), 32, Null_Address);
      if R = Null_Address or else S = Null_Address or else ECDSA_SIG_set0 (Signature, R, S) /= 1 then
         BN_free (R);
         BN_free (S);
         ECDSA_SIG_free (Signature);
         Fail ("ECDSA_SIG_set0");
      end if;
      declare
         Result : aliased String (1 .. 80);   --  72 at most for P-256
         Cursor : aliased Address := Result'Address;
         Length : constant int := i2d_ECDSA_SIG (Signature, Cursor'Access);
      begin
         ECDSA_SIG_free (Signature);
         if Length not in 1 .. Result'Length then
            Fail ("i2d_ECDSA_SIG");
         end if;
         return Result (1 .. Natural (Length));
      end;
   end Der_Of;

   function Raw_Of (Der : String) return String is
      Cursor    : aliased Address := Start_Of (Der);
      Signature : constant Address := d2i_ECDSA_SIG (Null_Address, Cursor'Access, long (Der'Length));
      Result    : String (1 .. 64);
   begin
      if Signature = Null_Address then
         Fail ("d2i_ECDSA_SIG");
      end if;
      if BN_bn2binpad (ECDSA_SIG_get0_r (Signature), Result (1)'Address, 32) /= 32
        or else BN_bn2binpad (ECDSA_SIG_get0_s (Signature), Result (33)'Address, 32) /= 32
      then
         ECDSA_SIG_free (Signature);
         Fail ("BN_bn2binpad");
      end if;
      ECDSA_SIG_free (Signature);
      return Result;
   end Raw_Of;

   ---------------------------------------------------------------------------------------------------------------
   --  Verifying and signing

   function Digest_For (Kind : Key_Kind) return Address is
     (if Kind = Ed25519 then Null_Address else EVP_sha256);

   function Verify (Key : Public_Key; Message : String; Signed : String) return Boolean is
      Context : Address;
      Status  : int := 0;
   begin
      if Key.Reference.Kind = None or else Signed'Length = 0
        or else (Key.Reference.Kind in Ec_P256 | Ed25519 and then Signed'Length /= Signature_Bytes)
      then
         return False;
      end if;
      declare
         Checked : constant String := (if Key.Reference.Kind = Ec_P256 then Der_Of (Signed) else Signed);
      begin
         Context := EVP_MD_CTX_new;
         if Context /= Null_Address
           and then EVP_DigestVerifyInit
             (Context, Null_Address, Digest_For (Key.Reference.Kind), Null_Address, Key.Reference.Handle) = 1
         then
            Status := EVP_DigestVerify
              (Context, Start_Of (Checked), Checked'Length, Start_Of (Message), Message'Length);
         end if;
         EVP_MD_CTX_free (Context);
      end;
      if Status /= 1 then
         Clear_Errors;
      end if;
      return Status = 1;
   end Verify;

   function Sign (Key : Private_Key; Message : String) return String is
      Context : constant Address := EVP_MD_CTX_new;
      Result  : aliased String (1 .. Max_Rsa_Signature_Bytes);   --  8192-bit RSA at most
      Length  : aliased size_t := Result'Length;
      Status  : int := 0;
   begin
      if Context /= Null_Address
        and then EVP_DigestSignInit
          (Context, Null_Address, Digest_For (Key.Reference.Kind), Null_Address, Key.Reference.Handle) = 1
      then
         Status := EVP_DigestSign (Context, Result'Address, Length'Access, Start_Of (Message), Message'Length);
      end if;
      EVP_MD_CTX_free (Context);
      if Status /= 1 then
         Fail ("EVP_DigestSign");
      end if;
      if Key.Reference.Kind = Ec_P256 then
         return Raw_Of (Result (1 .. Natural (Length)));
      end if;
      return Result (1 .. Natural (Length));
   end Sign;

end Sparrow.Crypto.Public_Keys;
