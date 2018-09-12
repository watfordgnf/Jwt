JSON Web Token  for .Net
===========

Provides support for JWT. 
This library aims to propose performant JWT primitives. 

[![Build status](https://ci.appveyor.com/api/projects/status/7lt4w59vy0v60s1b?svg=true)](https://ci.appveyor.com/project/ycrumeyrolle/jwt)
 [![CodeFactor](https://www.codefactor.io/repository/github/ycrumeyrolle/jwt/badge)](https://www.codefactor.io/repository/github/ycrumeyrolle/jwt)

## Versions
Current version - 0.1.0

## Usage
### JWT validation
````
    var key = new SymmetricJwk { K = "R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU" };
    var validationParameters = new TokenValidationBuilder()
				   .RequireSignature(key)
                                   .RequireAudience("valid_audience>")
				   .RequireIssuer("<valid_issuer>")
				   .Build()

    using (var reader = new JsonWebTokenReader())
    {
      var result = _reader.TryReadToken("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.2U33urP5-MPw1ipbwEP4nqvEqlZiyUG9Hxi8YS_RQVk");
      if (result.Success)
      {
        Console.WriteLine("The token is " + result.Token);
      }
      else
      {      
        Console.WriteLine("Failed to read the token. Reason: " + result.Status);
      }
    }
````

### JWT creation
````
    var descriptor = new JwsDescriptor()
    {
      Key = new SymmetricJwk { K = "R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU", Alg = "HS256" };,
      ExpirationTime = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
      IssuedAt = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
      Issuer = "https://idp.example.com/",
      Audience = "636C69656E745F6964"
    };

    using (var writer = new JsonWebTokenWriter())
    {
      string token = writer.WriteToken(descriptor);
    }
````
## Performances
See [benchmarks](Benchmark.md) for details. 
This library is about **3x** faster than the Microsoft.IdentityModel.Tokens.Jwt when decoding and validating the token, and **2.25x** faster when writing a JWS of common size, with only 1/4 of memory allocation.

The main reason of the speed of this library is the usage of the new API provided in .NET Core 2.0 and .NET Core 2.1.

## Supported JWT
* [JWS](https://tools.ietf.org/html/rfc7515) 
* [Nested JWT](https://tools.ietf.org/html/rfc7519#appendix-A.2): JWE with JWS as payload (know as JWE or Encrypted JWS)
* [Plaintext JWE](https://tools.ietf.org/html/rfc7519#appendix-A.1): JWE with plaintext as payload
* Binary JWE: JWE with binary as payload
* [Unsecure JWT](https://tools.ietf.org/html/rfc7515#appendix-A.5): JWS without signature

## Supported algorithms
### JWS signing algorithms
| "alg" Param Value | Digital Signature or MAC Algorithm        
|--------------|-------------------------------                 
| HS256        | HMAC using SHA-256                             
| HS384        | HMAC using SHA-384                             
| HS512        | HMAC using SHA-512                             
| RS256        | RSASSA-PKCS1-v1_5 using SHA-256                
| RS384        | RSASSA-PKCS1-v1_5 using SHA-384                
| RS512        | RSASSA-PKCS1-v1_5 using SHA-512                
| ES256        | ECDSA using P-256 and SHA-256                  
| ES384        | ECDSA using P-384 and SHA-384                  
| ES512        | ECDSA using P-521 and SHA-512                  
| PS256        | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 
| PS384        | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 
| PS512        | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 
| none         | No digital signature or MAC performed          

### JWE encryption algorithms
| "enc" Param Value | Content Encryption Algorithm                            
|---------------|----------------------------------                           
| A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm 
| A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm 
| A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm 
| A128GCM       | AES GCM using 128-bit key                                   
| A192GCM       | AES GCM using 192-bit key                                   
| A256GCM       | AES GCM using 256-bit key                                   

### JWE content encryption key algorithm
| "alg" Param Value  | Key Management Algorithm                                                    
|--------------------|--------------------                                                                       
| RSA1_5             | RSAES-PKCS1-v1_5                                                              
| RSA-OAEP           | RSAES OAEP using default parameters                                           
| RSA-OAEP-256       | RSAES OAEP using SHA-256 and MGF1 with SHA-256                                
| A128KW             | AES Key Wrap with default initial value using 128-bit key                     
| A192KW             | AES Key Wrap with default initial value using 192-bit key                     
| A256KW             | AES Key Wrap with default initial value using 256-bit key                     
| dir                | Direct use of a shared symmetric key as the CEK                               
| ECDH-ES            | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF 
| ECDH-ES+A128KW     | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"                        
| ECDH-ES+A192KW     | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"                        
| ECDH-ES+A256KW     | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"                        
| A128GCMKW          | Key wrapping with AES GCM using 128-bit key                                   
| A192GCMKW          | Key wrapping with AES GCM using 192-bit key                                   
| A256GCMKW          | Key wrapping with AES GCM using 256-bit key                                   
