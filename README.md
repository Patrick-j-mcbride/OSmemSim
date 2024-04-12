
# Memory Simulation Program
Patrick McBride
## Overview

This program is designed to simulate different memory management techniques, such as Virtual Storage Paging (VSP), Segmentation (SEG), and Paging (PAG). It supports various algorithms for memory allocation including first-fit, best-fit, and worst-fit depending on the memory management policy selected.

The program models the process of admitting processes into memory, their execution, and their completion, while managing memory allocation and deallocation dynamically. The memory state is output at each time interval, showing processes arriving, being moved into memory, completing, and the current state of the memory map.

## Prerequisites

- Python 3.10

## How to Run

1. Ensure Python 3.10 is installed on your system.
2. Place the program file and any required workload files in the same directory.
3. Open a terminal or command prompt in the directory containing the program file.
4. Run the program with the following command:
   ```
   python MemorySim.py
   ```

Follow the on-screen prompts to specify the memory size, management policy, and workload file as required.