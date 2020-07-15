<div align="center"><img src="https://user-images.githubusercontent.com/45048351/87528259-f8834280-c695-11ea-9886-5a0d60b4c977.png" width=500/> </div>

<br/>

## <div align="center"> STATUS </div>
<div align="center"> 
<span margin=15><img src=https://img.shields.io/github/workflow/status/ilyagrishkov/libtraceroute/Rust?style=for-the-badge&logo=appveyor/></span>
<span margin=15><img src=https://img.shields.io/github/license/ilyagrishkov/libtraceroute?style=for-the-badge&logo=appveyor/></span>
<span margin=15><img src=https://img.shields.io/badge/Rust-1.44.1-orange?style=for-the-badge&logo=appveyor/></span>
 
</div>

## <div align="center"> OVERVIEW </div>
**Libtraceroute** is a cross-platform traceroute library for Rust, that allows displaying possible routes (paths) and measuring transit delays of packets across an Internet Protocol (IP) network. Libtraceroute uses ![pnet](https://github.com/libpnet/libpnet), a low-level networking library, to send and capture packets on datalink layer, which allows it to operate without root priviledges. 


<br/><br/>

## <div align="center"> FEATURES </div>
**Libtraceroute** allows to configure the following parameters:
- [REQUIRED] Destination address
- Maximum number of hops
- Port
- [WIP] Number of queries per hop
- [WIP] Timeoute per query
- [WIP] Network interface 
- [WIP] Protocol

<br/><br/>

## <div align="center"> USAGE </div>

To use **libtraceroute** in your project, add the following to your Cargo.toml:

```
[dependencies]
libtraceroute = "0.1.0"
```

**NOTE!** If you are using Windows, then follow these instructions to make ![pnet](https://github.com/libpnet/libpnet) work:
> ### Windows
> * You must use a version of Rust which uses the MSVC toolchain
> * You must have [WinPcap](https://www.winpcap.org/) or [npcap](https://nmap.org/npcap/) installed
>   (tested with version WinPcap 4.1.3) (If using npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode")
> * You must place `Packet.lib` from the [WinPcap Developers pack](https://www.winpcap.org/devel.htm)
>   in a directory named `lib`, in the root of this repository. Alternatively, you can use any of the
>   locations listed in the `%LIB%`/`$Env:LIB` environment variables. For the 64 bit toolchain it is
>   in `WpdPack/Lib/x64/Packet.lib`, for the 32 bit toolchain, it is in `WpdPack/Lib/Packet.lib`.
  
Source: https://github.com/libpnet/libpnet/blob/master/README.md
<div align="center">
</div>
