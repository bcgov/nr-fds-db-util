set define off

/* *********************************************************************************
   Create this function logged in as the owning schema.
   If schema is new, create schema first.
************************************************************************************ */
CREATE OR REPLACE 
FUNCTION get_s3_presigned_url(p_bucket         IN VARCHAR2
                            , p_object         IN VARCHAR2
                            , p_public_key     IN VARCHAR2
                            , p_secret_key     IN VARCHAR2
                            , p_host           IN VARCHAR2
                            , p_expiry_seconds IN NUMBER   DEFAULT 3600)
RETURN VARCHAR2
AS
/* ************************************************************************************************************
   Builds a pre-signed URL to GET an S3 object, including calculation of an AWS v4
   signature as per 
   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-calculations
   
   Params
      p_bucket         - bucket name with no slashes (e.g. 'rlosde')
      p_object         - object path including slashes 
                       (e.g. '/myparentfolder/mychildfolder/myobject.obj' or '/myfile.jpg' for root file)
      p_public_key     - AWS Access Key
      p_secret_key     - AWS Secret Access Key
      p_host           - FQDN of S3 host (e.g. 'nrs.objectstore.gov.bc.ca')
      p_expiry_seconds - URL expires after this many seconds (e.g. 1 hour = 3600). Defaults to 1 hour.


***************************************************************************************************************** */
    c_aws_access_key_id     CONSTANT VARCHAR2(100) := p_public_key;
    c_aws_secret_access_key CONSTANT VARCHAR2(100) := p_secret_key;
    c_region                CONSTANT VARCHAR2(50) := 'us-east-1';
    c_method                CONSTANT VARCHAR2(10) := 'GET';
    c_host                  CONSTANT VARCHAR2(100) := p_host;
    c_canonical_uri         CONSTANT VARCHAR2(100) := '/' || p_bucket || p_object;
    c_iso8601_timestamp     CONSTANT VARCHAR2(25) := TO_CHAR(CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS DATE), 'YYYYMMDD"T"HH24MISS"Z"');
    c_date                  CONSTANT VARCHAR2(10) := SUBSTR(c_iso8601_timestamp,1,8);
    c_service               CONSTANT VARCHAR2(2) := 's3';
    c_signature_version     CONSTANT VARCHAR2(13) := 'aws4_request';
    --(spec says hashed SHA256 empty string for GET requests - only UNSIGNED-PAYLOAD appears to work and does not get pre-hashed)
    c_payload               CONSTANT VARCHAR2(16) := 'UNSIGNED-PAYLOAD';
    l_payload_hash          VARCHAR2(64);
    l_canonical_querystring VARCHAR2(1000);
    l_canonical_headers     VARCHAR2(1000);
    l_signed_headers        VARCHAR2(100);
    l_canonical_request     VARCHAR2(2000);
    l_string_to_sign        VARCHAR2(2000);
    l_signature             VARCHAR2(64);
    l_presigned_url         VARCHAR2(2000);

    PROCEDURE debugraw(p_debug IN RAW
                     , p_label IN VARCHAR2)
    IS 
    BEGIN
      DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------');
      DBMS_OUTPUT.PUT_LINE(p_label);
      DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------');
      DBMS_OUTPUT.PUT_LINE(TO_CHAR(p_debug));
      DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------');
    END;

    PROCEDURE debugit(p_debug IN VARCHAR2
                    , p_label IN VARCHAR2)
    IS
    BEGIN
      DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------');
      DBMS_OUTPUT.PUT_LINE(p_label);
      DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------');
      DBMS_OUTPUT.PUT_LINE(p_debug);
      DBMS_OUTPUT.PUT_LINE('--------------------------------------------------------');
    END;

    FUNCTION uri(v_string         IN VARCHAR2
               , b_parm_value     IN BOOLEAN DEFAULT FALSE) 
    RETURN VARCHAR2
    IS
    BEGIN
      --parm value of true will escape things like '/' that you may not want
      RETURN UTL_URL.ESCAPE(v_string,b_parm_value);
    END;


    FUNCTION calculate_signature (
      p_secret_key     IN VARCHAR2,
      p_region         IN VARCHAR2,
      p_service        IN VARCHAR2,
      p_string_to_sign IN VARCHAR2
    ) RETURN RAW IS
      c_date_key       RAW(128);
      c_region_key     RAW(128);
      c_service_key    RAW(128);
      l_signing_key    RAW(128);
      l_signature      RAW(128);
    BEGIN
      c_date_key := dbms_crypto.mac(UTL_I18N.STRING_TO_RAW(c_date,'AL32UTF8'),DBMS_CRYPTO.HMAC_SH256,UTL_I18N.STRING_TO_RAW('AWS4' || p_secret_key,'AL32UTF8'));
      debugraw(c_date_key,'date key generated in function');
      c_region_key := dbms_crypto.mac(UTL_I18N.STRING_TO_RAW(p_region,'AL32UTF8'),DBMS_CRYPTO.HMAC_SH256,c_date_key);
      debugraw(c_region_key,'region key generated in function');
      c_service_key := dbms_crypto.mac(UTL_I18N.STRING_TO_RAW(p_service,'AL32UTF8'),DBMS_CRYPTO.HMAC_SH256,c_region_key);
      debugraw(c_service_key,'service key generated in function');
      l_signing_key := dbms_crypto.mac(UTL_I18N.STRING_TO_RAW('aws4_request','AL32UTF8'),DBMS_CRYPTO.HMAC_SH256,c_service_key);
      debugraw(l_signing_key,'signing key generated in function');
      l_signature := dbms_crypto.mac(UTL_RAW.CAST_TO_RAW(p_string_to_sign),DBMS_CRYPTO.HMAC_SH256,l_signing_key);

      debugraw(l_signature,'sig generated in function');
      RETURN l_signature;
    END;
BEGIN

    -- Construct the canonical query string - should service be s3??????
    l_canonical_querystring := uri('X-Amz-Algorithm=AWS4-HMAC-SHA256') || 
                               '&' || uri('X-Amz-Credential') || '=' || uri(c_aws_access_key_id || '/' || c_date || '/' || c_region || '/' || c_service || '/' || c_signature_version,TRUE) || 
                               '&' || uri('X-Amz-Date=' || c_iso8601_timestamp) ||
                               '&' || uri('X-Amz-Expires=' || TO_CHAR(p_expiry_seconds)) ||
                               '&' || uri('X-Amz-SignedHeaders=') || uri('host');--;x-amz-content-sha256;x-amz-date',TRUE);
    debugit(l_canonical_querystring,'l_canonical_querystring');
    -- Construct the canonical headers and signed headers
    l_canonical_headers := 'host:' || c_host;-- || CHR(10) ||
                           --   'x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' || CHR(10) ||
                           --   'x-amz-date:'|| c_iso8601_timestamp;
    debugit(l_canonical_headers,'l_canonical_headers');
    l_signed_headers := 'host';--;x-amz-content-sha256;x-amz-date';
    debugit(l_signed_headers,'l_signed_headers');

    -- Hash the payload - intentionally not hashing though spec could be interpreted to require pre-hashing of this element
    l_payload_hash := c_payload;

    -- Construct the canonical request
    l_canonical_request := c_method || CHR(10) ||
                           c_canonical_uri || CHR(10) ||
                           l_canonical_querystring || CHR(10) ||
                           l_canonical_headers || CHR(10) || CHR(10) || -- NOTE: extra lf is required!
                           l_signed_headers || CHR(10) ||
                           l_payload_hash;
    debugit(l_canonical_request,'l_canonical_request');

    -- Construct the string to sign
    l_string_to_sign := 'AWS4-HMAC-SHA256' || CHR(10) ||
                        c_iso8601_timestamp || CHR(10) ||
                        c_date || '/' || c_region || '/' || c_service || '/' || c_signature_version || CHR(10) ||
                        LOWER(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(l_canonical_request), DBMS_CRYPTO.HASH_SH256));
    debugit(l_string_to_sign,'l_string_to_sign');
    
    -- Calculate the signature
    l_signature := calculate_signature(c_aws_secret_access_key, c_region, c_service, l_string_to_sign);
    debugit(l_signature,'l_signature');

    -- Construct the pre-signed URL
    l_presigned_url := 'https://' || c_host || c_canonical_uri || '?' || l_canonical_querystring || '&X-Amz-Signature=' || LOWER(RAWTOHEX(l_signature));

    DBMS_OUTPUT.PUT_LINE(l_presigned_url);
    RETURN l_presigned_url;
END;
/

GRANT EXECUTE ON get_s3_presigned_url TO the;

select get_s3_presigned_url(p_bucket => 'rlosde'
                          , p_object => '/resultsvctesttag2.jpg'
                          , p_public_key => 'xxxxxxx'
                          , p_secret_key => 'xxxxxxx'
                          , p_host => 'nrs.objectstore.gov.bc.ca') 
  from dual;

  