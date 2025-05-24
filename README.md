<div align="center">
  <picture>
  <img width="300" height="300" src="./logo.png">
  </picture>

# Interstellar

![Lua](https://img.shields.io/badge/lua-%232C2D72.svg?style=for-the-badge&logo=lua&logoColor=white)
![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

</div>

Committing atrocious acts of "why do we have this".\
Feel free to roast all the problems with this thing while I casually add things.\
This repository contains the files themselves, simply to be used as includes for other projects.

Some parts of this project doesn't need to be all included, like LXZ.

## Dangers
Do note that this basically has access to raw memory & libraries that could put you at risk.\
You are responsible for what happens with such functionality.

Do note as well that this build is a culmination of personal tinkering with LuaJIT, there will be issues overtime as changes are made.

## Building
Keep in mind that I do use vcpkg for simplifying the build process on my end, this is a list of them you may need, some of these also require some dependencies themselves for compiling:
- cpr
- libsodium
- openssl
- ixwebsocket
- zlib
- zstd
- liblzma
- bzip2
- bxzstr
- restinio
- nlohmann-json