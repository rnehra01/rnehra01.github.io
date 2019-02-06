---
layout: post
current: post
cover: "assets/images/brainwaves-cover.jpg"
navigation: True
title: "Brainwaves Cyber Security Hackathon"
date: 2019-02-06 05:45:00
tags: hackathon security
class: post-template
subclass: 'post'
disqus: True
author: rnehra01
---

This is the fifth edition of Brainwaves hackathon. The challenges are based on filesystems i.e. how data is stored in the hard disk. We are provided with 2 dumps of a hard disk.

<h3>Dump 1</h3>
<blockquote>
<p>The first sector of the hard disk is been modified. To load the boot loader successfully at every boot process we need to fix it. Your task is to fix the first sector and upload it back to us. Corrupted bytes  of the partition entries  are replaced  with value "CC". So you need to fix  these fields only.</p>
</blockquote>
According to <a href="https://en.wikipedia.org/wiki/Master_boot_record">wiki</a>, the first sector is a special boot sector called master boot record (MBR). After analyzing the given dump using <code>hexl-mode</code> in emacs, I found the corrupted <code>cc</code> bytes.

<pre>
000001b0: cd10 ac3c 0075 f4c3 608d 3b68 0000 0020  ...<.u..`.;h...
000001c0: 2100 debe 122c 0008 0000 <mark>cccc cccc</mark> 00be  !....,..........
000001d0: 132c 075d 0459 00f8 0a00 00f0 0a00 005d  .,.].Y.........]
000001e0: 0559 07fe ffff <mark>cccc cccc</mark> 00d0 e31d 00fe  .Y..............
000001f0: ffff 0ffe ffff 00b8 f91d 00a0 3e1c 55aa  ............>..U
</pre>

According to <a href="https://en.wikipedia.org/wiki/Master_boot_record#Sector_layout">MBR layout</a>, the master partition table start at address <code>1BE</code> and ends with boot signature <code>55AA</code>. The partition table consists of 4 entries and each entry looks like:
<img src="/assets/images/PartitionTables.png" alt="Partition Entry">
Based on the above information, the 4 partition entries in MBR are (the values have been converted from little-endian to big-endian):

<table id="part-table">
<tbody>
<tr>
<th>Boot indicator</th>
<th>CHS(start)</th>
<th>Partition type</th>
<th>CHS(end)</th>
<th>Starting sector</th>
<th>Partition Size</th>
</tr>
<tr>
<td>00</td>
<td>002120</td>
<td>de</td>
<td>2c12be</td>
<td>00000800</td>
<td>cccccccc</td>
</tr>
<tr class="even">
<td>00</td>
<td>2c13be</td>
<td>07</td>
<td>59045d</td>
<td>000af800</td>
<td>000af000</td>
</tr>
<tr>
<td>00</td>
<td>59055d</td>
<td>07</td>
<td>fffffe</td>
<td>cccccccc</td>
<td>1de3d000</td>
</tr>
<tr class="even">
<td>00</td>
<td>fffffe</td>
<td>0f</td>
<td>fffffe</td>
<td>1df9b800</td>
<td>1c3ea000</td>
</tr>
</tbody>
</table>

To fix the first 4 corrupted bytes, I need to find the size of first partition which can be calculated as difference of <code>CHS_END</code> and <code>CHS_START</code>. But first the CHS values needs to be decoded and converted in units of sectors. After reading this <a href="https://thestarman.pcministry.com/asm/mbr/PartTables.htm#Decoding">post</a>, I wrote a script that decode the 3 byte CHS hex value.

{% highlight python %}
inp = 0x5d0559		# 3 byte CHS 

head = inp >> 16
sect =  (inp & 0x003F00) >> 8
cyn = ((inp & 0x00C000) >> 6) | (inp & 0x0000FF)

print('CHS : ', cyn, head, sect)     # CHS: 89, 93, 5
{% endhighlight %}

The decoded CHS values can be converted into sectors using <code>(CYLINDER*<i>heads_per_cylinder</i> + HEAD )*<i>sectors_per_head</i> + SECTORS</code> but I needed the system constants <code><i>heads_per_cylinder</i></code> and <code><i>sectors_per_head</i></code>.

To calculate these constants, I used the values of 2<sup>nd</sup> partition. The first equation came using partition size and second using <code>starting sector(LBA)</code> entry which is equal to <code>CHS_FIRST(in sectors)-1</code>. Solving these 2 equations, we get

<pre>
<i>heads_per_cylinder</i> = 255
<i>sectors_per_head</i> = 63
</pre>

Now the size of partition 1 came out 716800 (0x000af000). Similarly I calculated <code>starting sector (LBA)</code> 0x0015e800.

After putting these values in the dump (converted to little-endian in the dump), it looked like

<pre>
000001b0: cd10 ac3c 0075 f4c3 608d 3b68 0000 0020  ...<.u..`.;h... 
000001c0: 2100 debe 122c 0008 0000 <mark>00f0 0a00</mark> 00be  !....,..........
000001d0: 132c 075d 0459 00f8 0a00 00f0 0a00 005d  .,.].Y.........]
000001e0: 0559 07fe ffff <mark>00e8 1500</mark> 00d0 e31d 00fe  .Y..............
000001f0: ffff 0ffe ffff 00b8 f91d 00a0 3e1c 55aa  ............>.U.
</pre>

<h6>Questions based on dump 1</h6>
<blockquote>
Q1. How many primary partitions are there in the hard disk dump?
</blockquote>

<pre>
3, the 4<sup>th</sup> partition is an extended partition because its partition type is <mark>0f</mark>
and others are primary partitions.
</pre>

<blockquote>
Q2. What is the disk signature of the hard disk for the given dump?
</blockquote>

<pre>
<mark>55AA</mark>. The last 2 bytes of the first sector.
</pre>

<blockquote>
Q3. How many NTFS partitions are there?
</blockquote>

<pre>
2, partition type of NTFS is <mark>07</mark>.
</pre>

<blockquote>
Q4. What is the size of hard disk in MBs?
</blockquote>

<pre>
It can be calculated by adding size of the partitions and multiplying by
bytes_per_sector(0x200).
</pre>

<h3>Dump 2</h3>

<blockquote>
The first sector of 2<sup>nd</sup> partition is modified to make the partition unusable by the operating system. Your task is to fix the first sector  and upload it back to us. MFT table of the partition is at the offset 0x1d3aa000 bytes from starting in the hard disk.
</blockquote>

<pre>
00000000: <mark>cc</mark>52 904e 5446 <mark>cc</mark>20 2020 2000 0208 0000  .R.NTF.    .....
00000010: 0000 0000 00f8 0000 3f00 ff00 00f8 0a00  ........?.......
00000020: 0000 0000 8000 8000 <mark>cccc cccc cccc cccc</mark>  ................
00000030: <mark>cccc cccc cccc cccc</mark> 0200 0000 0000 0000  .t..............
</pre>

The first 2 corrupted bytes can be easily fixed if you look at <a href="https://en.wikipedia.org/wiki/NTFS#Partition_Boot_Sector">wiki</a>. The next 8 bytes at address 0x28 represents partition size which can looked from the partition size entry corresponding to partition2 in the  <a href="#part-table">partition table</a>.

The next 8 bytes represents <a href="https://en.wikipedia.org/wiki/NTFS#Master_File_Table">MFT</a> offset from start of partition. It was calculated as difference of starting byte of 2<sup>nd</sup> partition (calculated by multiplying <code>starting sector</code> and <code>bytes_per_sector</code>) and given absolute address of MFT which came out to be <code>0x74aa000</code> bytes. Now it needed to be converted in units of clusters which was done by dividing <code>bytes_per_sector</code> (0x200) and <code>sectors_per_cluster</code> (0x08). And I went to address <code>0x74aa000</code> and found the MFT was there so the calculations were correct.
<pre id="dump2_fixed">
074aa000: 4649 4c45 3000 0300 2f4c 4000 0000 0000  FILE0.../L@.....
074aa010: 0100 0100 3800 0100 9801 0000 0004 0000  ....8...........
074aa020: 0000 0000 0000 0000 0700 0000 0000 0000  ................
074aa030: 0300 ffff 0000 0000 1000 0000 6000 0000  ............`...
074aa040: 0000 1800 0000 0000 4800 0000 1800 0000  ........H.......
074aa050: 78af 695d 9cd6 d001 78af 695d 9cd6 d001  x.i]....x.i]....
074aa060: 78af 695d 9cd6 d001 78af 695d 9cd6 d001  x.i]....x.i]....
074aa070: 0600 0000 0000 0000 0000 0000 0000 0000  ................
074aa080: 0000 0000 0001 0000 0000 0000 0000 0000  ................
074aa090: 0000 0000 0000 0000 3000 0000 6800 0000  ........0...h...
074aa0a0: 0000 1800 0000 0300 4a00 0000 1800 0100  ........J.......
074aa0b0: 0500 0000 0000 0500 78af 695d 9cd6 d001  ........x.i]....
074aa0c0: 78af 695d 9cd6 d001 78af 695d 9cd6 d001  x.i]....x.i]....
074aa0d0: 78af 695d 9cd6 d001 0040 0000 0000 0000  x.i].....@......
074aa0e0: 0040 0000 0000 0000 0600 0000 0000 0000  .@..............
074aa0f0: 0403 2400 5300 4f00 4300 4700 4500 4e00  ..$.S.O.C.G.E.N
074aa100: 8000 0000 4800 0000 0100 4000 0000 0600  ....H.....@.....
074aa110: 0000 0000 0000 0000 3f00 0000 0000 0000  ........?.......
</pre>

This is how the dump looks after fixing it.

<pre>
00000000: eb52 904e 5446 5320 2020 2000 0208 0000  .R.NTFS    .....
00000010: 0000 0000 00f8 0000 3f00 ff00 00f8 0a00  ........?.......
00000020: 0000 0000 8000 8000 00f0 0a00 0000 0000  ................
00000030: aa74 0000 0000 0000 0200 0000 0000 0000  .t..............
</pre>

And on running <code>file</code> on the fixed dump, then it showed all the attributes of the partition

<pre>
rnehra@pc ~> file dump2_fixed
dump2_fixed: DOS/MBR boot sector, code offset 0x52+2, OEM-ID "NTFS    ", sectors/cluster 8, Media descriptor 0xf8, sectors/track 63, heads 255, hidden sectors 718848, dos < 4.0 BootSector (0x80), FAT (1Y bit by descriptor); NTFS, sectors/track 63, sectors 716800, $MFT start cluster 29866, $MFTMirror start cluster 2, bytes/RecordSegment 2^(-1*246), clusters/index block 1, serial number 040ae5d9dae5d8c72
</pre>

<h6>Questions based on dump 2</h6>
<blockquote>
Q5. What is the size of cluster in bytes?
</blockquote>

<pre>
4096. Multiply <code>bytes_per_sector</code> (0x200) and <code>sectors_per_cluster</code> (0x08)
</pre>

<blockquote>
Q6. At what offset from the starting of partition the MFT table resides?
</blockquote>

<pre>
0x74aa000
</pre>

<blockquote>
Q7. What is the name of fist file?
</blockquote>

<pre>
$SOCGEN.
Visible in last lines of <a href="#dump2_fixed">first sector</a> of the partition
</pre>

<blockquote>
Q8. Which is the first non-system or non-Meta file in MFT entry?
</blockquote>

<pre>
MYDATA.TXT
Look at the location of non-Meta file <a href="https://en.wikipedia.org/wiki/NTFS#Metafiles">here</a>.
</pre>

This is a good but easy online hackathon which requires knowledge of boot sector, filesystems and bootloaders basics. So I recommend the organisers that they can increase the difficulty a bit but I give them full marks for choosing a topic that teaches more about the system which I use everyday.