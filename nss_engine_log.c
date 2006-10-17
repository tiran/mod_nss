/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*  _________________________________________________________________
**
**  Logfile Support
**  _________________________________________________________________
*/

#include "mod_nss.h"
#include "prerror.h"

#define NSPR_ERROR_BASE			PR_NSPR_ERROR_BASE
#define NSPR_MAX_ERROR			(PR_MAX_ERROR - 1)
#define LIBSEC_ERROR_BASE		(-8192)
#define LIBSEC_MAX_ERROR		(LIBSEC_ERROR_BASE + 155)
#define LIBSSL_ERROR_BASE		(-12288)
#define LIBSSL_MAX_ERROR		(LIBSSL_ERROR_BASE + 102)

typedef struct l_error_t {
    int errorNumber;
    const char *errorString;
} l_error_t;

l_error_t libsec_errors[] = {
    {  0, "I/O Error" },
    {  1, "Library Failure" },
    {  2, "Bad data was received" },
    {  3, "Security library: output length error" },
    {  4, "Security library has experienced an input length error" },
    {  5, "Security library: invalid arguments" },
    {  6, "Certificate contains invalid encryption or signature algorithm" },
    {  7, "Security library: invalid AVA" },
    {  8, "Certificate contains an invalid time value" },
    {  9, "Certificate is improperly DER encoded" },
    { 10, "Certificate has invalid signature" },
    { 11, "Certificate has expired" },
    { 12, "Certificate has been revoked" },
    { 13, "Certificate is signed by an unknown issuer" },
    { 14, "Invalid public key in certificate" },
    { 15, "The security password entered is incorrect" },
    { 16, "SEC_ERROR_UNUSED" },
    { 17, "Security library: no nodelock" },
    { 18, "Problem using certificate or key database" },
    { 19, "Out of Memory" },
    { 20, "Certificate is signed by an untrusted issuer" },
    { 21, "Peer's certificate has been marked as not trusted" },
    { 22, "Certificate already exists in your database" },
    { 23, "Downloaded certificate's name duplicates one already in your database" },
    { 24, "Error adding certificate to database" },
    { 25, "Error refiling the key for this certificate" },
    { 26, "The private key for this certificate cannot be found in key database" },
    { 27, "This certificate is valid" },
    { 28, "This certificate is not valid" },
    { 29, "Cert Library: No Response" },
    { 30, "The certificate issuer's certificate has expired. Check your system date and time" },
    { 31, "The CRL for the certificate's issuer has expired. Update it or check your system date and time" },
    { 32, "The CRL for the certificate's issuer has an invalid signature" },
    { 33, "New CRL has an invalid format" },
    { 34, "Certificate extension value is invalid" },
    { 35, "Certificate extension not found" },
    { 36, "Issuer certificate is invalid" },
    { 37, "Certificate path length constraint is invalid" },
    { 38, "Certificate usages field is invalid" },
    { 39, "**Internal ONLY module**" },
    { 40, "The key does not support the requested operation" },
    { 41, "Certificate contains unknown critical extension" },
    { 42, "New CRL is not later than the current one" },
    { 43, "Not encrypted or signed: you do not yet have an email certificate" },
    { 44, "Not encrypted: you do not have certificates for each of the recipients" },
    { 45, "Cannot decrypt: you are not a recipient, or matching certificate and private key not found" },
    { 46, "Cannot decrypt: key encryption algorithm does not match your certificate" },
    { 47, "Signature verification failed: no signer found, too many signers found, or improper or corrupted data" },
    { 48, "Unsupported or unknown key algorithm" },
    { 49, "Cannot decrypt: encrypted using a disallowed algorithm or key size" },
    { 50, "XP_Fortezza card has not been properly initialized. Please remove it and return it to your issuer" },
    { 51, "XP_No Fortezza cards Found" },
    { 52, "XP_No Fortezza card selected" },
    { 53, "XP_Please select a personality to get more info on" },
    { 54, "XP_Personality not found" },
    { 55, "XP_No more information on that Personality" },
    { 56, "XP_Invalid Pin" },
    { 57, "XP_Couldn't initialize Fortezza personalities" },
    { 58, "No KRL for this site's certificate has been found" },
    { 59, "The KRL for this site's certificate has expired" },
    { 60, "The KRL for this site's certificate has an invalid signature" },
    { 61, "The key for this site's certificate has been revoked" },
    { 62, "New KRL has an invalid format" },
    { 63, "security library: need random data" },
    { 64, "security library: no security module can perform the requested operation" },
    { 65, "The security card or token does not exist, needs to be initialized, or has been removed" },
    { 66, "security library: read-only database" },
    { 67, "No slot or token was selected" },
    { 68, "A certificate with the same nickname already exists" },
    { 69, "A key with the same nickname already exists" },
    { 70, "error while creating safe object" },
    { 71, "error while creating baggage object" },
    { 72, "Couldn't remove the principal" },
    { 73, "Couldn't delete the privilege" },
    { 74, "This principal doesn't have a certificate" },
    { 75, "Required algorithm is not allowed" },
    { 76, "Error attempting to export certificates" },
    { 77, "Error attempting to import certificates" },
    { 78, "Unable to import. Decoding error. File not valid" },
    { 79, "Unable to import. Invalid MAC. Incorrect password or corrupt file" },
    { 80, "Unable to import. MAC algorithm not supported" },
    { 81, "SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE" },
    { 82, "Unable to import. File structure is corrupt." },
    { 83, "Unable to import. Encryption algorithm not supported." },
    { 84, "Unable to import. File version not supported." },
    { 85, "SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT" },
    { 86, "Unable to import. Same nickname already exists in database." },
    { 87, "The user pressed cancel." },
    { 88, "Not imported, already in database." },
    { 89, "Message not sent." },
    { 90, "Certificate key usage inadequate for attempted operation." },
    { 91, "Certificate type not approved for application." },
    { 92, "Address in signing certificate does not match address in message headers." },
    { 93, "Unable to import. Error attempting to import private key." },
    { 94, "Unable to import. Error attempting to import certificate chain." },
    { 95, "Unable to export. Unable to locate certificate or key by nickname." },
    { 96, "Unable to export. Private Key could not be located and exported." },
    { 97, "Unable to export. Unable to write the export file." },
    { 98, "Unable to import. Unable to read the import file." },
    { 99, "Unable to export. Key database corrupt or deleted." },
    { 100, "Unable to generate public/private key pair." },
    { 101, "Password entered is invalid. Please pick a different one." },
    { 102, "Old password entered incorrectly. Please try again." },
    { 103, "Certificate nickname already in use." },
    { 104, "Peer FORTEZZA chain has a non-FORTEZZA Certificate." },
    { 105, "A sensitive key cannot be moved to the slot where it is needed." },
    { 106, "Invalid module name." },
    { 107, "Invalid module path/filename" },
    { 108, "Unable to add module" },
    { 109, "Unable to delete module" },
    { 110, "New KRL is not later than the current one." },
    { 111, "New CKL has different issuer than current CKL. Delete current CKL" },
    { 112, "The Certifying Authority for this certificate is not permitted to issue a certificate with this name" },
    { 113, "The key revocation list for this certificate is not yet valid" },
    { 114, "The certificate revocation list for this certificate is not yet valid" },
    { 115, "The requested certificate could not be found" },
    { 116, "The signer's certificate could not be found" },
    { 117, "The location for the certificate status server has invalid format" },
    { 118, "The OCSP response cannot be fully decoded; it is of an unknown type" },
    { 119, "The OCSP server returned unexpected/invalid HTTP data" },
    { 120, "The OCSP server found the request to be corrupted or improperly formed" },
    { 121, "The OCSP server experienced an internal error" },
    { 122, "The OCSP server suggests trying again later" },
    { 123, "The OCSP server requires a signature on this request" },
    { 124, "The OCSP server has refused this request as unauthorized" },
    { 125, "The OCSP server returned an unrecognizable status" },
    { 126, "The OCSP server has no status for the certificate" },
    { 127, "You must enable OCSP before performing this operation" },
    { 128, "You must set the OCSP default responder before performing this operation" },
    { 129, "The response from the OCSP server was corrupted or improperly formed" },
    { 130, "The signer of the OCSP response is not authorized to give status for this certificate" },
    { 131, "The OCSP response is not yet valid (contains a date in the future)" },
    { 132, "The OCSP response contains out-of-date information" },
    { 133, "SEC_ERROR_DIGEST_NOT_FOUND - Digest not found in S/MIME message." },
    { 134, "SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE - Unsupported or unknown message type in S/MIME message." },
    { 135, "SEC_ERROR_MODULE_STUCK - PK11 module is stuck." },
    { 136, "SEC_ERROR_BAD_TEMPLATE - Bad template found when decoding DER." },
    { 137, "SEC_ERROR_CRL_NOT_FOUND" },
    { 138, "SEC_ERROR_REUSED_ISSUER_AND_SERIAL" },
    { 139, "SEC_ERROR_BUSY" },
    { 140, "SEC_ERROR_EXTRA_INPUT" },
    { 141, "SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE" },
    { 142, "SEC_ERROR_UNSUPPORTED_EC_POINT_FORM" },
    { 143, "SEC_ERROR_UNRECOGNIZED_OID" },
    { 144, "SEC_ERROR_OCSP_INVALID_SIGNING_CERT - OCSP signer certificate not found, not trusted or invalid." },
    { 145, "SEC_ERROR_REVOKED_CERTIFICATE_CRL - This certificate has been revoked." },
    { 146, "SEC_ERROR_REVOKED_CERTIFICATE_OCSP - This certificate has been revoked." },
    { 147, "SEC_ERROR_CRL_INVALID_VERSION" },
    { 148, "SEC_ERROR_CRL_V1_CRITICAL_EXTENSION" },
    { 149, "SEC_ERROR_CRL_UNKNOWN_CRITICAL_EXTENSION" },
    { 150, "SEC_ERROR_UNKNOWN_OBJECT_TYPE" },
    { 151, "SEC_ERROR_INCOMPATIBLE_PKCS11" },
    { 152, "SEC_ERROR_NO_EVENT" },
    { 153, "SEC_ERROR_CRL_ALREADY_EXISTS" },
    { 154, "SEC_ERROR_NOT_INITIALIZED" },
    { 155, "SEC_ERROR_TOKEN_NOT_LOGGED_IN" }
};

l_error_t libnss_errors[] = {
    {  0, "Client does not support high-grade encryption" },
    {  1, "Client requires high-grade encryption which is not supported" },
    {  2, "No common encryption algorithm(s) with client" },
    {  3, "Unable to find the certificate or key necessary for authentication" },
    {  4, "Unable to communicate securely wih peer: peer's certificate was rejected" },
    {  5, "Unused SSL error #5" },
    {  6, "Protocol error" },
    {  7, "Protocol error" },
    {  8, "Unsupported certificate type" },
    {  9, "Client is using unsupported SSL version" },
    { 10, "Unused SSL error #10" },
    { 11, "The public key in the server's own certificate does not match its private key" },
    { 12, "Requested domain name does not match the server's certificate" },
    { 13, "SSL_ERROR_POST_WARNING" },
    { 14, "peer only supports SSL version 2, which is locally disabled" },
    { 15, "SSL has received a record with an incorrect Message Authentication Code" },
    { 16, "SSL has received an error indicating an incorrect Message Authentication Code" },
    { 17, "SSL client cannot verify your certificate" },
    { 18, "The server has rejected your certificate as revoked" },
    { 19, "The server has rejected your certificate as expired" },
    { 20, "Cannot connect: SSL is disabled" },
    { 21, "Cannot connect: SSL peer is in another Fortezza domain" },
    { 22, "An unknown SSL cipher suite has been requested" },
    { 23, "No cipher suites are present and enabled in this program" },
    { 24, "SSL received a record with bad block padding" },
    { 25, "SSL received a record that exceeded the maximum permissible length" },
    { 26, "SSL attempted to send a record that exceeded the maximum permissible length" },
    { 27, "SSL received a malformed Hello Request handshake message" },
    { 28, "SSL received a malformed Client Hello handshake message" },
    { 29, "SSL received a malformed Server Hello handshake message" },
    { 30, "SSL received a malformed Certificate handshake message" },
    { 31, "SSL received a malformed Server Key Exchange handshake message" },
    { 32, "SSL received a malformed Certificate Request handshake message" },
    { 33, "SSL received a malformed Server Hello Done handshake message" },
    { 34, "SSL received a malformed Certificate Verify handshake message" },
    { 35, "SSL received a malformed Client Key Exchange handshake message" },
    { 36, "SSL received a malformed Finished handshake message" },
    { 37, "SSL received a malformed Change Cipher Spec record" },
    { 38, "SSL received a malformed Alert record" },
    { 39, "SSL received a malformed Handshake record" },
    { 40, "SSL received a malformed Application Data record" },
    { 41, "SSL received an unexpected Hello Request handshake message" },
    { 42, "SSL received an unexpected Client Hello handshake message" },
    { 43, "SSL received an unexpected Server Hello handshake message" },
    { 44, "SSL received an unexpected Certificate handshake message" },
    { 45, "SSL received an unexpected Server Key Exchange handshake message" },
    { 46, "SSL received an unexpected Certificate Request handshake message" },
    { 47, "SSL received an unexpected Server Hello Done handshake message" },
    { 48, "SSL received an unexpected Certificate Verify handshake message" },
    { 49, "SSL received an unexpected Cllient Key Exchange handshake message" },
    { 50, "SSL received an unexpected Finished handshake message" },
    { 51, "SSL received an unexpected Change Cipher Spec record" },
    { 52, "SSL received an unexpected Alert record" },
    { 53, "SSL received an unexpected Handshake record" },
    { 54, "SSL received an unexpected Application Data record" },
    { 55, "SSL received a record with an unknown content type" },
    { 56, "SSL received a handshake message with an unknown message type" },
    { 57, "SSL received an alert record with an unknown alert description" },
    { 58, "SSL peer has closed the connection" },
    { 59, "SSL peer was not expecting a handshake message it received" },
    { 60, "SSL peer was unable to succesfully decompress an SSL record it received" },
    { 61, "SSL peer was unable to negotiate an acceptable set of security parameters" },
    { 62, "SSL peer rejected a handshake message for unacceptable content" },
    { 63, "SSL peer does not support certificates of the type it received" },
    { 64, "SSL peer had some unspecified issue with the certificate it received" },
    { 65, "SSL experienced a failure of its random number generator" },
    { 66, "Unable to digitally sign data required to verify your certificate" },
    { 67, "SSL was unable to extract the public key from the peer's certificate" },
    { 68, "Unspecified failure while processing SSL Server Key Exchange handshake" },
    { 69, "Unspecified failure while processing SSL Client Key Exchange handshake" },
    { 70, "Bulk data encryption algorithm failed in selected cipher suite" },
    { 71, "Bulk data decryption algorithm failed in selected cipher suite" },
    { 72, "Attempt to write encrypted data to underlying socket failed" },
    { 73, "MD5 digest function failed" },
    { 74, "SHA-1 digest function failed" },
    { 75, "MAC computation failed" },
    { 76, "Failure to create Symmetric Key context" },
    { 77, "Failure to unwrap the Symmetric key in Client Key Exchange message" },
    { 78, "SSL Server attempted to use domestic-grade public key with export cipher suite" },
    { 79, "PKCS11 code failed to translate an IV into a param" },
    { 80, "Failed to initialize the selected cipher suite" },
    { 81, "Failed to generate session keys for SSL session" },
    { 82, "Server has no key for the attempted key exchange algorithm" },
    { 83, "PKCS#11 token was inserted or removed while operation was in progress" },
    { 84, "No PKCS#11 token could be found to do a required operation" },
    { 85, "Cannot communicate securely with peer: no common compression algorithm(s)" },
    { 86, "Cannot initiate another SSL handshake until current handshake is complete" },
    { 87, "Received incorrect handshakes hash values from peer" },
    { 88, "The certificate provided cannot be used with the selected key exchange algorithm" },
    { 89, "There are no trusted Certificate Authorities for signing SSL client certificates" },
    { 90, "Client's SSL session ID not found in server's session cache" },
    { 91, "Peer was unable to decrypt an SSL record it received" },
    { 92, "Peer received an SSL record that was longer than is permitted" },
    { 93, "Peer does not recognize and trust the CA that issued your certificate" },
    { 94, "Peer received a valid certificate, but access was denied" },
    { 95, "Peer could not decode an SSL handshake message" },
    { 96, "Peer reports failure of signature verification or key exchange" },
    { 97, "Peer reports negotiation not in compliance with export regulations" },
    { 98, "Peer reports incompatible or unsupported protocol version" },
    { 99, "Server requires ciphers more secure than those supported by client" },
    { 100, "Peer reports it experienced an internal error" },
    { 101, "Peer user canceled handshake" },
    { 102, "Peer does not permit renegotiation of SSL security parameters" }
};

void nss_die(void) 
{
    /*
     * This is used for fatal errors and here
     * it is common module practice to really
     * exit from the complete program. 
     */ 
    exit(1); 
}

void nss_log_nss_error(const char *file, int line, int level, server_rec *s)
{
    const char *err;
    PRInt32 error;

    error = PR_GetError();

    if ((error >= NSPR_ERROR_BASE) && (error <= NSPR_MAX_ERROR)) {
        return; /* We aren't logging NSPR errors */
    } else if ((error >= LIBSEC_ERROR_BASE) &&
        (error <= LIBSEC_MAX_ERROR)) {
        err = libsec_errors[error-LIBSEC_ERROR_BASE].errorString;
    } else if ((error >= LIBSSL_ERROR_BASE) &&
        (error <= LIBSSL_MAX_ERROR)) {
        err = libnss_errors[error-LIBSSL_ERROR_BASE].errorString;
    } else {
         err = "Unknown";
    }

    ap_log_error(file, line, level, 0, s,
                 "SSL Library Error: %d %s",
                 error, err);
}
