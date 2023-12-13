# IDA - Static analysis

Compile the the target application custom_compile. 
Try this exercise with all security options and stripped version first and then use the option 11 if needed. 


Run the instructions below for target_application and note down the behavior. 
 

```sh 
  ./target_application 
  ./target_application --help 
  ./target_application –l 

```

# Subviews
Sub views may allow you to better understand the behvior of the application. You can add windows through view­ > Open sub-views.
Open the different sub-views below to assist your search for an exploitable vulnerability.

 

## Strings  (Shift+f12) 
This window gives a good insight as to what the application is doing as a whole. 
Look at the present strings and note down interesting investigation points. 
Find text found when using the `-–help` command and other possible useful strings.

### Hint: 
<details><summary>Hint Strings list:</summary>

-  LOAD:00000000000005CA 00000007 C strcmp
-   LOAD:00000000000005D1 00000008 C fprintf 
-   LOAD:00000000000005D9 00000006 C fopen 
-   LOAD:00000000000005DF 00000007 C fclose 
-   LOAD:00000000000005E6 00000007 C memset
-   LOAD:00000000000005F2 00000007 C stderr 
-   LOAD:00000000000005F9 00000006 C fread
-   LOAD:0000000000000604 00000007 C fwrite 
-   .rodata:00000000000020A0 00000021 C Usage: ./target_application [-l] 
-   .rodata:0000000000002132 00000012 C done parsing file 
-   .rodata:0000000000002132 00000022 C Discovered interesting value: %\n 

</details>



## IDA VIEW / Proximity view (Space) 

This view allows to visually represent the code execution. The `Proximity browser` subview allows to see the x-refs flowchart.
Start by looking at the help text found previously and where its used. Double click the text from the strings view to see its location in the ida view.
Press space to switch between graph view and text view. If this fails to switch, this means you are not in an executable memory space.  

Looking at the ida subview in text form, you can see `DATA XREF: main+` in the comments below the help string. 
You can Double click the `main+`  or other function name comment to jump to the executable code section that reference it (the numbers tell you the distance in the memory space, the arrow tells you whether its upward or downward). 

Looking at the nodes of the control flow graph, you can see the jumps that are taken (red/green = conditional jump, blue = jump). 

At a minimum, from the `usage: ./target_application [-l]` node, trace back the jumps taken to the top of the main function. You can drag the view or double click the jump arrow to see the originating node. 

You can also navigate this view by selecting a function in the "Functions" sub-view pannel. 

You can navigate in the ida view by clicking function calls and then go back and forth by using the arrow buttons, by selecting main the functions or by pressing X to see the cross-references to the present location  within the program and selecting an address within main. 

Take a look at the other branching path with your array highlighted you can see that it does a bunch of stuff to your array. 
 
## Pseudo code view (F5) 

Switching between the `Pseudocode` and `IDA view` can help you understand the goal of the function as well as how the information is stored  within the memory space. 
To help keep track of code position, within the `Pseudocode`, right click and synchronize to the IDA view tab.


The use of the `Function Call` sub view can help you relate one function to another. Though its use is limited compared to other sub-views.
 

# Analysis 

Depending on the security features used at compile some or no obfuscation will be present in the code.  
Nevertheless, Look around the different function calls and try to get a grasp as to what happens in each one of them.  

You can rename elements and functions to help your understanding if you are using a stripped file. 

 
<details><summary>Hint:</summary> 

You can hence see that there is two branching paths from the start one of which is short, quickly branches and prints the message found above.  

The starting main node also uses 1 or 2 system calls before branching to the help node. These calls set a value and copy a string value. Look around for what could be used. 

</details>

Find the function call that leads to a branching path and rename it to something fitting. 

 

<details><summary>Hint:</summary> 

Double clicking on `dword_4040` will show us that there are multiple double word values being stored one after the other. This is a typical representation for an array. Select all nearby dword and then click the convert to array. Then rename to an appropriate name by right clicking or pressing 'n'. 
</details>

Note down the location and address of the functions you might want to hook onto with Frida if you are using the stripped version of the target.  
For an easier : 

 

<details><summary>Hint Function list:</summary> 

-   Sub_132A: read input   @@ text:132A
-   Sub_11f9: license check @@ text:011f9
-   Sub_12A9: menu    @@text:12A9 
-   Sub_169c: parse file @@text:169C


</details>
 

<details><summary>Hint Function A:</summary>  

Sub_11f9:license check @@ text:011f9  checks twice per execution whether the license is valid or not. 

This is the prime hooking function for frida as it otherwise requires multiple manual interaction to stub out. 

</details>
 

<details><summary>Hint Function B:</summary> 

The following is an extract from Sub_169c:parse file @@text:169C. 

What is it doing ? How many characters are needed?  

```sh
  if ( stream ) {
    fread(ptr, v9, 1uLL, stream);
    
    for ( i = 0; i < v9 && *((_BYTE *)ptr + i); ++i ){
      switch ( *((_BYTE *)ptr + i) )
      
      { 
        
        case 'A': 
          v5 = 1; 
          break; 

        case 'B': 
          v6 = 1; 
          break; 

        case 'C': 
          v7 = 1;
          break; 

        default: 
          if ( v5 && v6 && v7 ) 
          { 
            printf( 
              "Discovered interesting value: %x\n", 
              (unsigned int)*((char *)ptr 
                            + *((char *)ptr + i) * *((char *)ptr + i) * *((char *)ptr + i) * *((char *)ptr + i))); 
            return 0LL; 
          } 
          break; 
      } 
    } 
```

<details><summary>Solution: :</summary> 

It reads a license passed through a file to check whether it contains 3+ characters and has an A, a B and a C. 

Passing it ABC1 will output a Segmentation Fault which is our attack vector. 

</details>
</details> 

# Security Features

Redo the first few step of this exercise using option 11, then compile a new version of `target_application` with only one security feature at a time and compare how the code changed from the option 11 code without security features.
## Stripped file

Stripped files will remove all symbols including debugging information and other data included in the executable such as their locations. 
<details><summary>Solution: :</summary> 

Look at the function names displayed in the Function pannel.

| Unstripped | Stripped |
| ------ | ------ |
| _start | start |
| _dl_relocate_static_pie | |
| deregister_tm_clones | deregister_tm_clones |
| register_tm_clones | nullsub_1 |
| __do_global_dtors_aux | __do_global_dtors_aux |
| frame_dummy | sub_4011D0 |
| license_check | sub_4011D6 |
| print_help | sub_401263 |
| get_line | sub_4012BD |
| main | main |
| parse_file | sub_4015E9 |
| _term_proc | _term_proc |

</details>

## Relro

RELRO stands for Relocation Read-Only. An Executable Linkable Format (ELF) binary uses a Global Offset Table (GOT) to resolve functions dynamically. When enabled, this security property makes the GOT within the binary read-only, which prevents some form of relocation attacks.
<details><summary>Solution: :</summary> 

Go at any two matching functions within the Relro and No-Relro files. Then take a look at the addresses of each of those functions. While the addresses are slightly different the Relro version does not show where the GOT starts.

| No Relro | Relro |
| ------ | ------ |
|    00000000004011D6    |    00000000000011F9    |

</details>

## Canary

Canaries are known values that are placed between a buffer and control data on the stack to monitor buffer overflows.
<details><summary>Solution: :</summary> 

The Canaries are checked twice during the executable. Once at 0000000000001060 and once at 0000000000004108. Try to familiarize yourself with how it looks in both the graph and text view as you'll find Canary to be easily identifiable in the future.

The content of the Canary subroutine is as follows:

.plt:0000000000001060 ___stack_chk_fail proc near             ; CODE XREF: sub_1209+A9↓p



.plt:0000000000001060                                         ; sub_12B9+7A↓p ...

.plt:0000000000001060                 jmp     cs:off_4018

.plt:0000000000001060 ___stack_chk_fail endp

</details>

## PIE

PIE stands for position-independent executable. As the name suggests, it's code that is placed somewhere in memory for execution regardless of its absolute address.

## NX

NX stands for "non-executable." It's often enabled at the CPU level, so an operating system with NX enabled can mark certain areas of memory as non-executable. Often, buffer-overflow exploits put code on the stack and then try to execute it. However, making this writable area non-executable can prevent such attacks. This property is enabled by default during regular compilation using gcc.

# IDA - Dynamic analysis

Dynamic analysis can be done on an executable leveraging the findings of static analysis. To access dynamic analysis in IDA, locate the "Play", "Pause" and "Stop" icons, located in the tool ribbon of IDA. To the right of those icons, you can find the debugger selection scroll-down menu, which usually displays "No debugger". Select your available debugger or install one. Assuming you are able to run the executable by pressing the "play" icon, you can right-click any address to put a break point (F2), to stop the execution at that point. You can then step-into (F7) or step-over (F8) the next instruction. Press the "Stop" icon then the "Play" icon again to see this behavior. 

It is also possible to edit the code of the executable as it runs to access parts of the memory you shouldn’t be able to. To do so, go to "Edit > Patch program > Assemble" with your cursor at the given address. This can be used to turn conditional jumps into the opposite jump such as JNZ into JZ, effectively allowing you to bypass some checks. Note that most assembly conditional checks have an alternative opposite. A quick online search will grant you a list of all assembly conditional checks.

One other key feature of dynamic analysis is the possibility to edit the registers as the code executes. This might even be required to advance into an executable regardless of if you edited the jumps. To edit registers locate the "General Registers" window located in the top right when the executable is being debugged. 
