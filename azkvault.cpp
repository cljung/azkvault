// basic-http-client.cpp
#include <iostream>
#include <sstream>
#include <sys/time.h>
#include <uuid/uuid.h>

#include "cpprest/details/basic_types.h"
#include "cpprest/http_client.h"
#include "cpprest/interopstream.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

#include "wascore/util.h"
#include "wascore/filestream.h"
#include "was/common.h"
#include "was/storage_account.h"
#include "was/blob.h"

using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;

// globals
utility::string_t clientId = "";
utility::string_t clientSecret = "";
utility::string_t keyVaultName = "";
utility::string_t blobContainer = "";
bool verbose = false;
//////////////////////////////////////////////////////////////////////////////
//
class KeyVaultClient
{
  public:
    utility::string_t tokenType;
    utility::string_t accessToken;
    utility::string_t keyVaultUrl;
    utility::string_t loginUrl;
    utility::string_t resourceUrl;
    utility::string_t keyVaultName;
    utility::string_t keyVaultRegion;

  private:
    int status_code;
    web::json::value secret;

  private:
    utility::string_t get_https_url( utility::string_t headerValue );
    pplx::task<void> GetLoginUrl();    
    pplx::task<void> get_secret( utility::string_t secretName );
    utility::string_t NewGuid();

  public:
    pplx::task<void> Authenticate( utility::string_t& clientId, utility::string_t& clientSecret, utility::string_t& keyVaultName );
    bool GetSecretValue( utility::string_t secretName, web::json::value& secret );
};
//////////////////////////////////////////////////////////////////////////////
// helper to generate a new guid (currently Linux specific, for Windows we 
// should use ::CoCreateGuid() 
utility::string_t KeyVaultClient::NewGuid()
{
    uuid_t uuid;
    uuid_generate_time_safe(uuid);
    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);
    utility::string_t guid = uuid_str;
    return guid;  
}
//////////////////////////////////////////////////////////////////////////////
// Call Azure KeyVault REST API to retrieve a secret
bool KeyVaultClient::GetSecretValue( utility::string_t secretName, web::json::value& secret )
{
    get_secret( secretName ).wait();
    secret = this->secret;
    return this->status_code == 200;
}
pplx::task<void> KeyVaultClient::get_secret( utility::string_t secretName )
{
    auto impl = this;
    // create the url path to query the keyvault secret
    utility::string_t url = "https://" + impl->keyVaultName + ".vault.azure.net/secrets/" + secretName + "?api-version=2015-06-01";
    http_client client( url ); 
    http_request request(methods::GET);
    request.headers().add("Accept", "application/json");   
    request.headers().add("client-request-id", NewGuid() );
    // add access token we got from authentication step
    request.headers().add("Authorization", impl->tokenType + " " + impl->accessToken );
    // Azure HTTP REST API call
    return client.request(request).then([impl](http_response response)
    {
      std::error_code err;
      impl->status_code = response.status_code();
      if ( impl->status_code == 200 ) {
         auto bodyStream = response.body();
         concurrency::streams::stringstreambuf sbuffer;
         auto& target = sbuffer.collection();
         bodyStream.read_to_end(sbuffer).get();
         impl->secret = web::json::value::parse( target.c_str(), err );
      } else {
        utility::string_t empty = "{\"id\":\"\",\"value\":\"\"}";
        impl->secret = web::json::value::parse( empty.c_str(), err );
      }
    });
}
 
//////////////////////////////////////////////////////////////////////////////
// helper to parse out https url in double quotes
utility::string_t KeyVaultClient::get_https_url( utility::string_t headerValue )
{ 
  size_t pos1 = headerValue.find("https://");
  if ( pos1 >= 0 ) {
     size_t pos2 = headerValue.find("\"", pos1+1);
     if ( pos2 > pos1 ) {
        utility::string_t url = headerValue.substr(pos1, pos2-pos1);
        headerValue = url;
     } else {
        utility::string_t url = headerValue.substr(pos1);
        headerValue = url;
     }
  }
  return headerValue;
}
//////////////////////////////////////////////////////////////////////////////
// Make a HTTP POST to oauth2 IDP source to get JWT Token containing
// access token & token type
pplx::task<void> KeyVaultClient::Authenticate( utility::string_t& clientId, utility::string_t& clientSecret, utility::string_t& keyVaultName )
{
    auto impl = this;
    impl->keyVaultName = keyVaultName;

    // make a un-auth'd request to KeyVault to get a response that contains url to IDP
    impl->GetLoginUrl().wait();

    // create the oauth2 authentication request and pass the clientId/Secret as app identifiers
    utility::string_t url = impl->loginUrl + "/oauth2/token";
    http_client client( url ); 
    utility::string_t postData = "resource=" + uri::encode_uri( impl->resourceUrl ) + "&client_id=" + clientId
                               + "&client_secret=" + clientSecret + "&grant_type=client_credentials";
    http_request request(methods::POST);
    request.headers().add("Content-Type", "application/x-www-form-urlencoded");
    request.headers().add("Accept", "application/json");   
    request.headers().add("return-client-request-id", "true");   
    request.headers().add("client-request-id", NewGuid() );
    request.set_body( postData );
    // response from IDP is a JWT Token that contains the token type and access token we need for
    // Azure HTTP REST API calls
    return client.request(request).then([impl](http_response response)
    {
        impl->status_code = response.status_code();
        if ( impl->status_code == 200 ) {
           auto bodyStream = response.body();
           concurrency::streams::stringstreambuf sbuffer;
           auto& target = sbuffer.collection();
           bodyStream.read_to_end(sbuffer).get();
           std::error_code err;
           web::json::value jwtToken = web::json::value::parse( target.c_str(), err );
           if ( err.value() == 0 ) {
              impl->tokenType = jwtToken["token_type"].as_string();
              impl->accessToken = jwtToken["access_token"].as_string();
          }
       }
    });
}
//////////////////////////////////////////////////////////////////////////////
// Make a HTTP Get to Azure KeyVault unauthorized which gets us a response 
// where the header contains the url of IDP to be used
pplx::task<void> KeyVaultClient::GetLoginUrl()
{
    auto impl = this;
    utility::string_t url = "https://" + impl->keyVaultName + ".vault.azure.net/secrets/secretname?api-version=2015-06-01";
    http_client client( url ); 
    return client.request(methods::GET).then([impl](http_response response)
    {
        impl->status_code = response.status_code();
        if ( impl->status_code == 401 ) {
           web::http::http_headers& headers = response.headers();
           impl->keyVaultRegion = headers["x-ms-keyvault-region"];
           const utility::string_t& wwwAuth = headers["WWW-Authenticate"];
           // parse WWW-Authenticate header into url links. Format:
           // Bearer authenticate="url", resource="url"
           utility::string_t delimiter = " ";
           size_t count = 0, start = 0, end = wwwAuth.find(delimiter);
           while (end != utility::string_t::npos)
           {
             utility::string_t part = wwwAuth.substr(start, end - start);
             if ( count == 1 ) {
                impl->loginUrl = impl->get_https_url( part );
             }
             start = end + delimiter.length();
             end = wwwAuth.find(delimiter, start);
             count++;
           }
           utility::string_t part = wwwAuth.substr(start, end - start);
           impl->resourceUrl = impl->get_https_url( part );
       }
    });
}
//////////////////////////////////////////////////////////////////////////////
// Read configFile where each line is in format key=value
void GetConfig(std::string configFile)
{
  std::ifstream fin(configFile);
  std::string line;
  std::istringstream sin;
  std::string val;

  while (std::getline(fin, line)) {
    sin.str(line.substr(line.find("=")+1));
    sin >> val;
    if (line.find("keyVaultName") != std::string::npos) {
      keyVaultName = val;
    }
    else if (line.find("clientId") != std::string::npos) {
      clientId = val;
    }
    else if (line.find("clientSecret") != std::string::npos) {
      clientSecret = val;
    }
    else if (line.find("blobContainer") != std::string::npos) {
      blobContainer = val;
    }
    else if (line.find("verbose") != std::string::npos) {
      if (val.find("true") != std::string::npos) {
        verbose = true;
      }
    }
    sin.clear();
  }
}
//////////////////////////////////////////////////////////////////////////////
//
int main(int argc, char* argv[])
{
    if ( argc < 2 ) {
       std::wcout << "syntax: azkvault secretname [localfile blobname]" << std::endl;
    }

    KeyVaultClient kvc;
    utility::string_t secretName = argv[1];
    utility::string_t fileName = "";
    utility::string_t blobName = "";

    if ( argc >= 4 ) {
       fileName = argv[2];
       blobName = argv[3];
    }

    /////////////////////////////////////////////////////////////////////////
    // load values from config file
    GetConfig("azkvault.conf");

    /////////////////////////////////////////////////////////////////////////
    // Authenticate with Azure AD
    std::wcout << "Authenticating for KeyVault " << keyVaultName.c_str() << "..." << std::endl;
    std::wcout << "clientId : " << clientId.c_str() << "..." << std::endl;

    kvc.Authenticate( clientId, clientSecret, keyVaultName ).wait();

    if ( verbose ) {
       std::wcout << "Azure Region: " << kvc.keyVaultRegion.c_str() << std::endl;
       std::wcout << "ResourceUrl : " << kvc.resourceUrl.c_str() << std::endl;
       std::wcout << "LoginUrl    : " << kvc.loginUrl.c_str() << std::endl;
       std::wcout << kvc.tokenType.c_str() << " " << kvc.accessToken.c_str() << std::endl;
    }

    /////////////////////////////////////////////////////////////////////////
    // Get Azure KeyVault secret
    std::wcout << "Querying KeyVault Secret " << secretName.c_str() << "..." << std::endl;
    web::json::value jsonSecret;
    bool rc = kvc.GetSecretValue( secretName, jsonSecret );

    if ( rc == false ) {
       std::wcout << "Secret doesn't exist" << std::endl;
       return 1;
    }
    std::wcout << "Secret ID   : " << jsonSecret["id"].as_string().c_str() << std::endl;
    std::wcout << "Secret Value: " << jsonSecret["value"].as_string().c_str() << std::endl;

    /////////////////////////////////////////////////////////////////////////
    // Upload file to blob container

    try {
      // Initialize Storage Account from KeyVault secret, which holds the connect string
      utility::string_t storage_connection_string = jsonSecret["value"].as_string();
      azure::storage::cloud_storage_account storage_account = azure::storage::cloud_storage_account::parse( storage_connection_string );

      // get container ref
      std::wcout << "Using Blob Container: " <<  blobContainer.c_str() << std::endl;
      azure::storage::cloud_blob_client blob_client = storage_account.create_cloud_blob_client();
      azure::storage::cloud_blob_container container = blob_client.get_container_reference( blobContainer );
      container.create_if_not_exists();

      time_t t = time(NULL);
      struct tm * curtime = localtime( &t );
      // upload file
      std::wcout << asctime(curtime) << ": Uploading file " <<  fileName.c_str() << std::endl;

      concurrency::streams::istream input_stream = concurrency::streams::file_stream<uint8_t>::open_istream( fileName ).get();
      azure::storage::cloud_block_blob blob1 = container.get_block_blob_reference( blobName );
      blob1.upload_from_stream(input_stream);
      input_stream.close().wait();

      t = time(NULL);
      curtime = localtime( &t );
      std::wcout << asctime(curtime) << ": Done!" << std::endl;
    } 
    catch (const azure::storage::storage_exception& e) {
        ucout << "Error: " << e.what() << std::endl;

        azure::storage::request_result result = e.result();
        azure::storage::storage_extended_error extended_error = result.extended_error();
        if (!extended_error.message().empty())
        {
            ucout << extended_error.message() << std::endl;
        }
    } catch (const std::exception& e) {
        ucout << "Error: " << e.what() << std::endl;
    }

    return 0;
}


