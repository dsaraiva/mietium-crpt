# Guiões das Sessões Laboratoriais

---
## Semana 5 Canal seguro entre Cliente/Servidor 

As classes [Cliente.java](Cliente.java),
[Servidor.java](Servidor.java) e [TServidor.java](TServidor.java)
implementam uma aplicação que permite a um número arbitrário de
clientes comunicar com um servidor que escuta num dado port
(e.g. 4567). O servidor atribui um número de ordem a cada cliente, e
simplesmente faz o _dump_ do texto enviado por cada cliente
(prefixando cada linha com o respectivo número de ordem). Quando um
cliente fecha a ligação, o servidor assinala o facto (e.g. imprimindo
[n], onde _n_ é o número do cliente).

Exemplo da execução do servidor (que comunica com 3 clientes):


```bash
$ java Servidor
1 : daskj djdhs slfghfjs askj
1 : asdkdh fdhss
1 : sjd
2 : iidhs
2 : asdjhf sdga
2 : sadjjd d dhhsj
3 : djsh
1 : sh dh d   d
3 : jdhd kasjdh as
2 : dsaj dasjh
3 : asdj dhdhsjsh
[3]
2 : sjdh
1 : dhgd ss
[1]
2 : djdj
[2]
```

Pretende-se:

 * Modificar as respectivas classes por forma a garantir a
   _confidencialidade_ e _integridade_ nas comunicações
   estabelecidas.
 * Para o efeito, deverá considerar uma cifra por blocos no modo que
   considerar mais apropriado.
  * Numa primeira fase, os segredos requeridos poderão ser guardados
    devidamente protegidos numa `KeyStore`.

Algumas classes relevantes (ver
[API](http://docs.oracle.com/javase/8/docs/api/)):

 * `java.math.BigInteger`
 * `java.net.ServerSocket`
 * `java.lang.Thread`
 * `java.net.Socket`


---
## Semana 4

Continuação da implementação do guião da semana 3.

---
## Semana 3

### Aplicação de Cifra

Pretende-se adaptar a aplicação desenvolvida na última aula para responder
aos seguintes requisitos:

 * O ficheiro que guarda a chave utilizada nas operações de cifra deve
   ser devidamente protegido;
 * Se o ficheiro cifrado for manipulado (alterado), o programa ao
   decifrar deverá detectar essa ocorrência;
 * Utilize uma cifra por blocos num modo apropriado.

Algumas classes relevantes (ver
[API](http://docs.oracle.com/javase/8/docs/api/)):

 * `java.security.KeyStore`
 * `java.security.KeyStore.SecretKeyEntry`
 * `javax.crypto.Mac`
 * `javax.crypto.spec.IvParameterSpec`

---
## Semana 2

### Cifra de ficheiro utilizando JCA/JCE

Pretende-se cifrar o conteudo de um ficheiro. Para tal far-se-á uso da
funcionalidade oferecida pela JCA/JCE, em particular implementação de
cifras simétricas.

O objectivo é então o de definir um pequeno programa Java que permita
cifrar/decifrar um ficheiro utilizando uma cifra simétrica
(e.g. RC4). A sua forma de utilização pode ser análoga a:

```
prog -genkey <keyfile>
prog -enc <keyfile> <infile> <outfile>
prog -dec <keyfile> <infile> <outfile>
```

Sugestões:

 * Para simplificar, pode começar por utilizar uma chave secreta fixa
   definida no código na forma de um array de bytes (i.e. implementar
   somente as opções -enc e -dec). Nesse caso, deverá utilizar a
   classe SecretKeySpec para a converter para o formato adequado.
 * Um segundo passo deverá consistir na implementação da opção
   -genkey. Aí surge o problema de guardar a chave no sistema de
   ficheiros: vamos começar por adoptar a solução mais simples (e
   insegura) - guardar a chave directamente num ficheiro sem qualquer
   tipo de protecção.

Algumas classes relevantes (ver [API](http://docs.oracle.com/javase/8/docs/api/)):

 * `javax.crypto.Cipher`
 *  `javax.crypto.KeyGenerator`
 * `javax.crypto.SecretKey (interface)`
 * `javax.crypto.spec.SecretKeySpec`
 * `java.security.SecureRandom`

---
## Semana 1

Os objectivos para a aula desta semana são:
 1. escolher e instalar o ambiente de programação _Java_ a utilizar nas aulas laboratoriais de Criptografia;
 1. familiarizar-se com os comandos essenciais do *GIT* por forma a interagir com o repositório pessoal e o da UC.
 1. registar-se no [GitHub](http://github.com) e criar o repositório que irá conter programas realizados ao longo do semestre;
 1. desenvolver um pequeno programa _Java_ para colocar no repositório pessoal e submeter a versão final para o repositório da UC.

### Apontadores úteis:
 * Linguagem de programação _Java_
   * [JDK SE](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
   * [Java API](http://docs.oracle.com/javase/8/docs/api/)
   * [Java tutorials](http://docs.oracle.com/javase/tutorial/)
 * *Git*
   * [site oficial](https://git-scm.com)
   * [TryIt!](http://try.github.io)
   * [GitHub's cheat sheet](https://training.github.com/kit/downloads/github-git-cheat-sheet.pdf), [Visual Git cheat sheet](http://ndpsoftware.com/git-cheatsheet.html)
   * [GitPro online book](https://git-scm.com/book/en/v2)
 * GitHub
   * <http://github.com> (signup, signin, etc.)
   * [GitHub desktop](https://desktop.github.com)
   * repositório da UC: <https://github.com/jba-uminho/mietium-crpt>

### Tarefas:
 1. *fork* do repositório da UC (ver [documentação](https://help.github.com/articles/fork-a-repo/))
 1. *clone" do repositório pessoal (ver https://help.github.com/articles/cloning-a-repository/)
 1. crie em `src/mycat` uma aplicação Java que se comporte como o comando *Unix* `cat` (i.e. copie o conteúdo de `stdin` para `stdout`)
 1. faça `commit`, `push`, etc. frequentemente por forma a manter o repositório pessoal actualizado
 1. quando finalizar o programa, submeta o programa realizado por intermédio de um `PullRequest` do GitHub (ver https://help.github.com/articles/using-pull-requests/)

---
