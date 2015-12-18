# Let's Encrypt module for Nginx

## Introduction

[TODO]

## Dependencies

To build this module you need all the tools installed which you would also need to
build the Nginx server alone. In addition you need `curl` to download the source code
of the server using make.

## Installation

  1. Download the NginX source code using:

        make source

  2. Configure, build and install the server with the module:

        make install

      With this step the server is compiled and installed in the `./run` directory.
      Don't worry, nothing is installed on your system outside this directory.
      
  3. Run the server:
  
        make run

    You can later stop the server with:
    
        make kill
        
## Configuration

  * The build process and the directories can be configured in the first few lines of
    the [Makefile](Makefile).

  * The server will run with a copy of the configuration file [example/nginx.conf](example/nginx.conf)
