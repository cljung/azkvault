# Azure KeyVault client in C++ for retrieving secrets

This sample code uses Azure KeyVault's REST API to retrieve a secret that contains a value of an Azure Storage Account connection string. It upload a file to a blob container using that connection string. 
Microsoft has a <a href="https://github.com/Azure/azure-storage-cpp" target="_blank">C++ Azure Storage Account library</a> if you need to build a solution in C++.
However, it only implements support for storage which means you have to implement the rest yourself using the REST APIs.

## Azure KeyVault secrets
In Azure KeyVault you can store certificates and secrets. Secrets can be sensitive data in plain text, like userids and passwords, or whatever you like. If you don't want to sensitive data in config files, perhaps because it is a remote device in a not entirely safe place, storing it as a secret in key vault and retrieving it at runtime can be a better solution. 
The benefit of using KeyVault secrets is that if you need to update connection strings, you only have to do it in KeyVault and not in all (remote?) places you have config files.

In order to retrieve secrets you first need to Authenticate with Azure AD. The Key Vault REST API is kind enough to pass the url of its OAuth endpoint in the HTTP Response if you make an unauthorized HTTP Request. This sample code takes advantage of that and does the following:

1. Makes a HTTP GET to your KeyVault endpoint asking for a bogus secret
2. Grab the OAuth endpoint in the header of the Response
3. Makes a HTTP POST to the OAuth endpoint with a clientId and clientSecret value proving it's a legitimate application
4. Saves the JWT Token returned on successfull login
5. Makes subsequent HTTP GET requests to Azure's KeyVault REST API to retrieve secrets

6. Use the Azure Storage C++ library to upload a file to blob storage.

## Config file
This sample stores the values of the KeyVault, clientId and clientSecret in a text file called azkvault.conf. It has the following content:
<pre>
<code>
verbose=false
keyVaultName=cljungkv01
clientId=...guid...
clientSecret=...guid...
blobContainer=my-sample-container
</code>
</pre>
You should grab the values in the Azure Portal and paste them in the file.

## Building the sample on Linux
Building this sample on an Ubuntu Linux is explanied in the README.md in <a href="https://github.com/Azure/azure-storage-cpp" target="_blank">azure-storage-cpp</a> github.
You need to git clone and build something called <a href="https://github.com/microsoft/cpprestsdk">Casablanca and azure-storage-cpp</a>. Casablanca is a C++ REST API client implementation by Microsoft which helps you build clients for any REST based solution. You will find Casablanca referenced from azure-storage-cpp.
WARNING - the instructions for some reason builds Casablanca as a debug build and azure-storage-cpp as a release build. I did a pure release build of them both.

In order to build and run this sample, you need to make sure that the ROOTDIR definition is currect. The ROOTDIR variable is the parent folder to azkvault, Casablanca and azure-storage-cpp.
The makefile grabs the parent folder of the current folder and uses as ROOTDIR.
<pre>
<code>
PWD=$(shell pwd)
ROOTDIR=$(shell dirname $(PWD))
</code>
</pre>
Depending on what you call the folders for your Casablanca and azure-storage-cpp builds you may need to change the CASABLANCA_BINDIR and the AZURECPP_BINDIR too. I called them build.release

## Running the sample
Modify the config file and then run azkvault on the command line with either 1 or 3 arguments. Running it with one argument will just retrieve the secret and display it.
<pre>
<code>
./azkvault my-top-secret-name
</code>
</pre>
Running the program with three argument will retrieve the secret and then upload the file to blob storage.
<pre>
<code>
./azkvault my-top-secret-name ./local-file.txt blob-file-name.txt
</code>
</pre>

