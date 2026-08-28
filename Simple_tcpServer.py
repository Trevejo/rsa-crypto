from socket import *

serverPort = 1300
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(("", serverPort))
serverSocket.listen(5)
print("TCP Server\n")
connectionSocket, addr = serverSocket.accept()
sentence = connectionSocket.recv(65000)

received = str(sentence, "utf-8")
print("Received From Client: ", received)

capitalizedSentence = sentence.upper()

connectionSocket.send(capitalizedSentence)

sent = str(capitalizedSentence, "utf-8")
print("Sent back to Client: ", sent)
connectionSocket.close()
