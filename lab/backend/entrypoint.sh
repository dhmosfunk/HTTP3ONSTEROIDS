#!/bin/bash

# Function to handle incoming HTTP requests and echo back the request
handle_request() {
  while IFS= read -r line; do
    if [[ "$line" == $'\r' ]]; then
      break
    fi
  done

  # HTTP response
  echo -e "HTTP/1.1 200 OK\r"
  echo -e "Content-Type: text/plain\r"
  echo -e "Connection: close\r"
  echo -e "\r"
  echo -e "Your HTTP request:\n"
  cat

  # Close the connection--http3 -H 'user-agent: mozilla'
HTTP/3 200
  echo -e "\r"
}

# Start the HTTP server using socat
socat TCP4-LISTEN:8080,fork EXEC:handle_request
