# CJ Assinaturas: Gerador e Verificador de Assinaturas RSA

Bem-vindo ao CJ Assinaturas, um programa simples para gerar e verificar assinaturas RSA em arquivos. Siga as instruções abaixo para utilizar o programa:

## Versão do Python:
- O programa foi desenvolvido utilizando Python 3.12.0. Para instalação: https://www.python.org/downloads/

## Execução do Programa:
- Para executar o programa, abra o terminal na pasta do projeto e digite `python3 main.py` ou `python main.py`.

## Operações Disponíveis:

### 1. Gerar Chave Pública e Privada:
- Escolha a opção `1` para gerar um novo par de chaves RSA.
- As chaves serão salvas no arquivo `keys.txt`.

### 2. Cifrar um Arquivo:
- Escolha a opção `2` para cifrar um arquivo.
- Certifique-se de ter as chaves geradas no arquivo `keys.txt`.
- O arquivo cifrado será salvo como `ciphertext.txt`.

### 3. Decifrar um Arquivo:
- Escolha a opção `3` para decifrar um arquivo cifrado.
- As chaves devem estar disponíveis no arquivo `keys.txt`.
- O resultado será salvo como `decipher.txt`.

### 4. Gerar Assinatura:
- Escolha a opção `4` para gerar uma assinatura para um arquivo.
- A assinatura será adicionada ao final do arquivo de sua escolha.

### 5. Verificar Assinatura:
- Escolha a opção `5` para verificar a assinatura de um arquivo a sua escolha.
- O programa imprimirá se a assinatura é válida ou inválida.

## Observações Importantes:
- O programa utiliza o algoritmo RSA com esquema de padding OAEP para melhorar a segurança.
- Ao gerar uma assinatura, o programa utiliza SHA3-256 como função de hash.
- Certifique-se de criar o arquivo `keys.txt` antes de realizar operações de cifragem, decifragem ou assinatura.
- Cuidado para não assinar, e depois gerar uma nova chave aleatória, pois a assinatura não será mais válida.
