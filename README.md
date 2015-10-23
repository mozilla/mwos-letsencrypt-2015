# Let's Encrypt Module for Nginx

## Introduction

[TODO]

## Installation

  1. Download the NginX source code using:

        make source

  2. Configure, build and install the server with the module:

        make install

      With this step the server is compiled and installed in the `./run` directory.
      Don't worry, nothing is installed on your system outside this directory.
      
  3. Run the server
  
        make run
        
## Configuration

  The server will run with a copy of the configuration file [conf/nginx.conf](conf/nginx.conf)
