# RSA sobre TCP: Alice e Bob

Implementacao didatica do algoritmo RSA integrada aos exemplos `Simple_tcpServer.py` e `simple_tcpClient.py`. O cliente representa **Alice** e o servidor representa **Bob**.

A evidencia visual da comunicacao no Wireshark nao esta incluida ainda. O roteiro para realizar as capturas na demonstracao esta na secao [Evidencia com Wireshark](#evidencia-com-wireshark).

## Objetivos da atividade

- Gerar um par de chaves RSA no cliente e outro par no servidor.
- Usar modulo RSA com exatamente 4096 bits.
- Trocar as chaves publicas em texto puro pela conexao TCP.
- Cifrar a mensagem de Alice com a chave publica de Bob.
- Fazer Bob decifrar a mensagem, converte-la para maiusculas e cifra-la com a chave publica de Alice.
- Fazer Alice decifrar e apresentar a resposta.
- Medir o tempo desde o inicio do programa cliente ate a apresentacao da mensagem em maiusculas.

## Arquivos

| Arquivo | Funcao |
| --- | --- |
| `Simple_tcpServer.py` | Bob: gera chaves, recebe a chave de Alice, decifra e responde. |
| `simple_tcpClient.py` | Alice: gera chaves, envia a chave publica, cifra a mensagem e calcula o RTT. |
| `rsa_4096.py` | Miller-Rabin, geracao de primos, chaves RSA, cifragem e decifragem. |
| `tcp_protocol.py` | Framing de mensagens JSON em uma conexao TCP. |

## Requisitos

- Python 3.8 ou superior.
- Nenhuma biblioteca externa: o projeto usa apenas a biblioteca padrao do Python.
- Duas maquinas na mesma rede para a demonstracao completa, ou `localhost` para um teste inicial.
- Porta TCP `1300` liberada no firewall da maquina de Bob.

## Como executar em duas maquinas

### 1. Bob inicia o servidor

Na maquina que atuara como servidor, execute:

```bash
python3 Simple_tcpServer.py
```

O servidor escuta em todas as interfaces (`0.0.0.0`) na porta `1300`. A geracao das chaves de 4096 bits pode levar alguns segundos. Aguarde a mensagem:

```text
[Bob] Aguardando Alice em 0.0.0.0:1300...
```

Descubra o endereco IP da maquina de Bob, por exemplo com `ip addr` no Linux ou `ipconfig` no Windows.

### 2. Alice inicia o cliente

Na maquina de Alice, substitua o endereco abaixo pelo IP de Bob:

```bash
python3 simple_tcpClient.py 192.168.78.169
```

O endereco `192.168.78.169` e o valor padrao herdado do exemplo original. Tambem e possivel informar outra porta:

```bash
python3 simple_tcpClient.py 192.168.78.169 --port 1300
```

A mensagem padrao enviada e:

```text
The information security is of significant importance to ensure the privacy of communications
```

Para testar outra mensagem sem alterar o codigo:

```bash
python3 simple_tcpClient.py 192.168.78.169 --message "uma mensagem de teste"
```

O servidor atende uma conexao por execucao. Para uma nova demonstracao, encerre ou aguarde o processo e execute o servidor novamente.

## Protocolo de comunicacao

As mensagens de aplicacao sao objetos JSON terminados por `\n`. Essa delimitacao e necessaria porque TCP e um fluxo de bytes e nao preserva fronteiras de mensagens.

1. Alice abre a conexao TCP com Bob.
2. Alice envia sua chave publica em texto puro:

```json
{"type":"public_key","role":"Alice","algorithm":"RSA-4096","bits":4096,"n":"...","e":"65537"}
```

3. Bob envia sua chave publica em texto puro no mesmo formato, com `role` igual a `Bob`.
4. Alice cifra a mensagem com `(n_Bob, e_Bob)` e envia um JSON com o resultado em Base64. O conteudo da mensagem nao aparece em texto puro no payload:

```json
{"type":"encrypted_message","algorithm":"RSAES-PKCS1-v1_5","encoding":"base64","ciphertext":"..."}
```

5. Bob usa sua chave privada para decifrar, converte o texto para maiusculas e cifra a resposta com a chave publica de Alice.
6. Bob envia a resposta como `encrypted_response`.
7. Alice decifra a resposta, apresenta o texto em maiusculas e imprime o RTT.

Os campos `n` e `e` sao convertidos para texto decimal no JSON para que a chave publica fique facilmente identificavel durante a analise do fluxo. O texto cifrado e Base64 apenas para transporte; Base64 nao e cifragem.

## Implementacao do RSA

Para uma chave RSA de 4096 bits, o programa faz o seguinte:

1. Gera dois primos provaveis `p` e `q`, cada um com 2048 bits.
2. Calcula `n = p * q` e repete a geracao se `n` nao tiver exatamente 4096 bits.
3. Calcula `phi(n) = (p - 1) * (q - 1)`.
4. Usa `e = 65537` como expoente publico.
5. Calcula `d`, o inverso modular de `e` modulo `phi(n)`.
6. Publica `(n, e)` e mantem `(n, d)` localmente.

A cifragem e a decifragem usam exponenciacao modular:

```text
c = m^e mod n
m = c^d mod n
```

Antes da exponenciacao, a mensagem recebe preenchimento `RSAES-PKCS1-v1_5` com bytes aleatorios. Isso permite transportar bytes de texto e evita que a mesma mensagem produza sempre o mesmo bloco cifrado. Para uso real, uma biblioteca criptografica auditada e RSA-OAEP seriam preferiveis; este projeto e voltado ao entendimento da atividade.

### Uso dos codigos fornecidos

- A funcao `is_probable_prime` reutiliza a estrutura do `primo_hyper.py`: pre-checagem por pequenos primos, decomposicao de `n - 1` e teste Miller-Rabin.
- Para numeros menores que `2**64`, sao mantidas as bases deterministicas fornecidas. Para candidatos de 2048 bits, sao usadas 12 bases aleatorias.
- `random_odd_candidate` implementa a ideia do `gen_4096.py`, ligando o bit mais alto. Tambem liga o bit mais baixo para evitar candidatos pares.
- A fonte de aleatoriedade foi trocada de `random` para `secrets`, pois os valores sao usados na geracao de chaves. O tamanho de 4096 bits se refere ao modulo `n`; gerar `p` e `q` com 4096 bits produziria uma chave de aproximadamente 8192 bits.

## RTT

O cronometro usa `time.perf_counter()` no cliente. A primeira medicao ocorre no inicio de `main`, antes da geracao das chaves e da conexao TCP. A segunda ocorre imediatamente depois do `print` que apresenta a mensagem maiuscula recebida.

Assim, o valor exibido e deliberadamente o tempo total da atividade:

```text
geracao da chave de Alice
+ conexao TCP
+ troca das chaves publicas
+ cifragem e envio
+ processamento de Bob
+ resposta, decifragem e apresentacao
```

Ele nao representa somente o atraso de rede. Essa definicao segue a observacao da atividade sobre os pontos inicial e final da contagem.

## Evidencia com Wireshark

Esta parte deve ser realizada posteriormente durante o teste em duas maquinas. Nenhuma captura ou print e afirmado como concluido neste repositorio.

1. Inicie a captura na interface de rede correta antes de executar Alice.
2. Use o filtro de exibicao:

```text
tcp.port == 1300
```

3. Execute Bob e Alice conforme as instrucoes anteriores.
4. Identifique o three-way handshake TCP (`SYN`, `SYN-ACK` e `ACK`).
5. Use **Follow > TCP Stream** no pacote da conexao para observar a ordem das mensagens.
6. Registre um pacote ou trecho contendo `"type":"public_key"`, mostrando que `n` e `e` foram trocados em texto puro.
7. Registre o trecho `"type":"encrypted_message"` e o campo `ciphertext` em Base64.
8. Registre a resposta `"type":"encrypted_response"`.
9. Compare a mensagem apresentada no terminal de Alice com o resultado recebido, sem esperar encontrar a mensagem original em texto puro no payload cifrado.
10. Inclua os prints dessas etapas no relatorio ou na demonstracao, conforme orientacao do professor.

O fato de a chave publica trafegar em texto puro e intencional nesta atividade. Sem autenticacao ou assinatura digital, um atacante poderia substituir chaves publicas; portanto, este protocolo nao deve ser usado como substituto de TLS em sistemas reais.

## Teste local rapido

Para validar a implementacao antes do teste entre maquinas, abra dois terminais na pasta do projeto. No primeiro:

```bash
python3 Simple_tcpServer.py
```

No segundo:

```bash
python3 simple_tcpClient.py 127.0.0.1
```

O cliente deve mostrar a mensagem em maiusculas e uma linha com o RTT total.
