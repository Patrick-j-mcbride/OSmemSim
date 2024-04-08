class Process:
    def __init__(self, pid, arrival_time, lifetime, memory_requirements):
        self.pid = pid
        self.arrival_time = arrival_time
        self.lifetime = lifetime
        self.memory_requirements = sum(memory_requirements[1:])
        self.segments = memory_requirements[1:]
        self.admission_time = None  # Time when the process is admitted to memory

    def __repr__(self):
        return f"Process(pid={self.pid}, arrival_time={self.arrival_time}, lifetime={self.lifetime}, memory_requirements={self.memory_requirements})"

class OutputBlock:
    def __init__(self, time):
        self.time = time
        self.events = []

    def add_event(self, event, memory_map=None):
        self.events.append([event, memory_map])

    def __str__(self):
        # Output the time block with first event on the same line
        output = f"t = {self.time}: {self.events[0][0]}\n"
        # Remove the first event from the list
        self.events = self.events[1:]
        # Output the rest of the events
        for event in self.events:
            if event[1] is not None:
                output += f"        {event[0]}\n"
                for line in event[1]:
                    output += f"                {line}\n"
            else:
                output += f"        {event[0]}\n"
        return output + "        "

    def __repr__(self):
        return self.__str__()
    
    def output_if_not_empty(self):
        if self.events:
            print(self)

class SimulatePAG:
    def __init__(self, processes, memory_size, page_size):
        self.processes = processes
        self.memory_size = memory_size
        self.page_size = page_size

        self.total_frames = memory_size // page_size
        self.memory_map = [None] * self.total_frames  # None indicates a free frame
        self.mmap_metadata = [None] * self.total_frames
        self.current_time = 0
        self.input_queue = []
        self.running_processes = []
        self.finished_processes = []
        self.output_blocks = []
        self.out = None
        self.simulate()

    def simulate(self):
        while self.processes or self.input_queue or self.running_processes:
            self.out = OutputBlock(self.current_time)
            self.update_completions()
            self.update_input_queue()
            self.update_queue()
            self.out.output_if_not_empty()
            self.current_time += 1
        top = sum([p.admission_time + p.lifetime - p.arrival_time for p in self.finished_processes])
        bottom = len(self.finished_processes)
        avg_turnaround_time = top / bottom
        print(f"Average Turnaround Time: {avg_turnaround_time}")
        
    def free_memory(self, pid):
        for i in range(self.total_frames):
            if self.memory_map[i] == pid:
                self.memory_map[i] = None
                self.mmap_metadata[i] = None

    def update_completions(self):
        for process in list(self.running_processes):
            if self.current_time >= process.admission_time + process.lifetime:
                self.free_memory(process.pid)
                self.running_processes.remove(process)
                self.finished_processes.append(process)
                self.out.add_event(f"Process {process.pid} completes")
                self.out.add_event("Memory Map: ", self.get_mmap())

    def update_input_queue(self):
        i = 0
        while i < len(self.processes):
            process = self.processes[i]
            if process.arrival_time == self.current_time:
                self.input_queue.append(process)
                self.processes.remove(process)
                self.out.add_event(f"Process {process.pid} arrives")
                self.out.add_event(self.get_input_queue())
            else:
                i += 1

    def get_mmap(self):
        out_mmap = []
        free_frames = self.memory_map.count(None)
        free_chunks = 0
        for i, pid in enumerate(self.memory_map):
            if free_chunks != 0 and pid is not None:
                start = (i-free_chunks)*self.page_size
                end = (free_chunks*self.page_size)-1 + start
                out_mmap.append(f"{start}-{end}: Free Frame(s)")
                free_frames -= free_chunks
                free_chunks = 0
            if pid is not None:
                out_mmap.append(f"{i*self.page_size}-{(i+1)*self.page_size-1}: {self.mmap_metadata[i]}")
            else:
                free_chunks += 1
            
        if free_frames > 0:
            out_mmap.append(f"{self.total_frames*self.page_size - free_frames*self.page_size}-{self.total_frames*self.page_size-1}: Free Frame(s)")
        return out_mmap

    def get_input_queue(self):
        out = "Input Queue:["
        for process in self.input_queue:
            out += f"{process.pid} "
        if out[-1] == " ":
            out = out[:-1]  # Remove the last space
        out += "]"
        return out
    
    def update_queue(self):
        i = 0
        while i < len(self.input_queue):
            process = self.input_queue[i]
            if self.allocate_memory(process):
                process.admission_time = self.current_time
                self.running_processes.append(process)
                self.input_queue.remove(process)
                self.out.add_event(f"MM moves Process {process.pid} to memory")
                self.out.add_event(self.get_input_queue())
                self.out.add_event("Memory Map: ", self.get_mmap())
            else:
                i += 1

    def allocate_memory(self, process):
        required_frames = (process.memory_requirements + self.page_size - 1) // self.page_size
        free_frames = self.memory_map.count(None)
        if free_frames < required_frames:
            return False
        allocated = 0
        for i in range(self.total_frames):
            if self.memory_map[i] is None:
                allocated += 1
                self.memory_map[i] = process.pid
                self.mmap_metadata[i] = f"Process {process.pid}, Page {allocated}"
                if allocated == required_frames:
                    return True
        return False

def read_workload_file(filename):
    processes = []
    with open(filename, 'r') as file:
        n = int(file.readline().strip())
        for _ in range(n):
            pid = file.readline().strip()
            arrival_time, lifetime = map(int, file.readline().strip().split())
            memory_requirements = list(map(int, file.readline().strip().split()))
            processes.append(Process(pid, arrival_time, lifetime, memory_requirements))
            file.readline()  # Skip the blank line
    return processes

def get_config():
    memory_size = int(input("Memory size: "))
    policy = int(input("Memory management policy (1 - VSP, 2 - PAG, 3 - SEG): "))
    if policy != 2:
        algorithm = int(input("Fit algorithm (1 - first-fit, 2 - best-fit, 3 - worst-fit): "))
        page_size = None
    else:
        page_size = int(input("Page/Frame size: "))
        algorithm = None
    filename = input("Enter the name of the workload file: ")
    return memory_size, policy, algorithm, page_size, filename

def simulate_vsp(processes, memory_size, algorithm):
    pass

def simulate_seg(processes, memory_size, algorithm):
    memory_map = [{'pid': None, 'start': 0, 'end': memory_size}]  # Initialize memory as entirely free

    def merge_free_spaces():
        # Merges adjacent free spaces in the memory map
        i = 0
        while i < len(memory_map) - 1:
            if memory_map[i]['pid'] is None and memory_map[i + 1]['pid'] is None:
                memory_map[i]['end'] = memory_map[i + 1]['end']
                del memory_map[i + 1]
            else:
                i += 1

    def allocate_memory(process):
        for segment_size in process.segments:
            hole = find_hole_for_segment(segment_size)
            if hole is None:
                return False
            # Allocate segment in the hole
            start, end = hole
            index = next(i for i, m in enumerate(memory_map) if m['start'] == start)
            memory_map.insert(index + 1, {'pid': process.pid, 'start': start, 'end': start + segment_size})
            if start + segment_size < end:
                memory_map[index]['start'] = start + segment_size
            else:
                del memory_map[index]
        process.admission_time = current_time
        return True

    def free_memory(pid):
        # Free memory occupied by the process's segments
        for m in memory_map:
            if m['pid'] == pid:
                m['pid'] = None
        merge_free_spaces()

    def find_hole_for_segment(segment_size):
        if algorithm == 1:  # First-fit
            for m in memory_map:
                if m['pid'] is None and (m['end'] - m['start']) >= segment_size:
                    return (m['start'], m['end'])
        elif algorithm == 2:  # Best-fit
            best_hole = None
            for m in memory_map:
                if m['pid'] is None and (m['end'] - m['start']) >= segment_size:
                    if best_hole is None or (m['end'] - m['start']) < (best_hole[1] - best_hole[0]):
                        best_hole = (m['start'], m['end'])
            return best_hole
        elif algorithm == 3:  # Worst-fit
            worst_hole = None
            for m in memory_map:
                if m['pid'] is None and (m['end'] - m['start']) >= segment_size:
                    if worst_hole is None or (m['end'] - m['start']) > (worst_hole[1] - worst_hole[0]):
                        worst_hole = (m['start'], m['end'])
            return worst_hole
        return None
    
    def add_memory_map(output):
        output += "\tMemory Map:\n"
        for m in memory_map:
            pass #TODO
        return output
    
    def add_input_queue(output):
        output += "\tInput Queue:["
        for process in input_queue:
            output += f"{process.pid} "
        output += "]\n"
        return output

    current_time = 0
    input_queue = []
    while processes or input_queue:
        time_block_output = ""
        # Process completions
        for p in [p for p in processes if p.admission_time is not None and current_time >= p.admission_time + p.lifetime]:
            time_block_output += f"\tProcess {p.pid} completes\n"
            free_memory(p.pid)
            processes.remove(p)
        # Process arrivals
        for p in [p for p in processes if p.arrival_time == current_time]:
            time_block_output += f"\tProcess {p.pid} arrives\n"
            input_queue.append(p)
            time_block_output = add_input_queue(time_block_output)
            time_block_output = add_memory_map(time_block_output)
        # Attempt to allocate memory for processes in the input queue
        for p in list(input_queue):
            if allocate_memory(p):
                time_block_output += f"\tMM moves process {p.pid} to memory\n"
                time_block_output = add_memory_map(time_block_output)
                input_queue.remove(p)

        if time_block_output != "":
            print(f"t = {current_time}:")
            print(time_block_output, end="")
        # Increment time
        current_time += 1


    # Calculate and print average turnaround time
    total_turnaround_time = sum([p.admission_time + p.lifetime - p.arrival_time for p in processes if p.admission_time is not None])
    average_turnaround_time = total_turnaround_time / len(processes) if processes else 0
    print(f"Average turnaround time: {average_turnaround_time:.2f}")

def main():
    memory_size, policy, algorithm, page_size, filename = get_config()
    processes = read_workload_file(filename)
    if policy == 1:
        simulate_vsp(processes, memory_size, algorithm)
    elif policy == 2:
        SimulatePAG(processes, memory_size, page_size)
    elif policy == 3:
        simulate_seg(processes, memory_size, algorithm)
    
def test_main():
        processes = read_workload_file('input1.txt')
        memory_size = 2000
        page_size = 400
        SimulatePAG(processes, memory_size, page_size)

if __name__ == "__main__":
    #main()
    test_main()
