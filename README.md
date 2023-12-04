This project consists of two main Python scripts: rawUDPClient.py and rawUDPServer.py. These scripts implement a file transfer protocol over raw UDP sockets.

### rawUDPClient.py

This script is the client-side application. It uses a GUI built with Tkinter to take user inputs for the local IP, remote IP, sending port, receiving port, destination port, file name, and save name.

The client starts by sending a READY message to the server. Once the server is online, the client sends the filename of the requested file. The server responds with the file size, and then the file transfer begins. The client saves the received file with the specified save name.

The client also includes a progress bar to show the progress of the file download.

### rawUDPServer.py

This script is the server-side application. It listens for incoming connections from clients. When a client sends a READY message, the server acknowledges it and waits for the filename. Once the filename is received, the server sends the file size and then starts the file transfer.

### Running the Scripts

To run these scripts, you need Python 3 installed on your machine. You can run the scripts using the following commands:

```python
python rawUDPClient.py
python rawUDPServer.py
```

Please ensure that the server script is running before starting the client script.

