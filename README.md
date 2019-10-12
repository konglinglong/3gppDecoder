3gppDecoder
=====

## 概述

使用RED语言实现的3GPP解码器，支持2G、3G、4G、5G等等等相关通信协议。

理论上，通过修改配置文件，可以解码wireshark现在以及未来支持的所有协议。

## 预览

<div align=center>
  <img src='https://github.com/konglinglong/3gppDecoder/blob/master/%E7%95%8C%E9%9D%A2.png' alt='preview' />
</div>

## 使用
#### 1. 从GitHub的releases页面下载[3gppDecoder-Release-XXX.zip](https://github.com/konglinglong/3gppDecoder/releases)
#### 2. 解压到一个文件夹，打开3gppDecoder.cfg配置文件：
 - 修改wireshark路径
 - 修改notepad++路径
 - 增加配置文件里面没有但你需要用到的协议（前提是你的wireshark版本支持）
