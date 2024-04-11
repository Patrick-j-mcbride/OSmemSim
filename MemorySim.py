import re
import copy


def format_tat(tat):
    return re.sub(r"\.(\d)0$", r".\1", tat)


class Process:
    def __init__(self, pid, arrival_time, lifetime, memory_requirements):
        self.pid = pid
        self.arrival_time = arrival_time
        self.lifetime = lifetime
        self.memory_requirements = sum(memory_requirements[1:])
        self.segments = memory_requirements[1:]
        self.num_segments = memory_requirements[0]
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
        while (
            self.processes or self.input_queue or self.running_processes
        ) and self.current_time < 100000:
            self.out = OutputBlock(self.current_time)
            self.update_completions()
            self.update_input_queue()
            self.update_queue()
            self.out.output_if_not_empty()
            self.current_time += 1
        top = sum(
            [
                p.admission_time + p.lifetime - p.arrival_time
                for p in self.finished_processes
            ]
        )
        bottom = len(self.finished_processes)
        avg_turnaround_time = top / bottom
        print(format_tat(f"Average Turnaround Time: {avg_turnaround_time:.2f}"))

    def free_memory(self, pid):
        for i in range(self.total_frames):
            if self.memory_map[i] == pid:
                self.memory_map[i] = None
                self.mmap_metadata[i] = None

    def update_completions(self):
        removals = []
        for process in self.running_processes:
            if self.current_time >= process.admission_time + process.lifetime:
                self.free_memory(process.pid)
                self.out.add_event(f"Process {process.pid} completes")
                self.out.add_event("Memory Map: ", self.get_mmap())
                self.finished_processes.append(process)
                removals.append(process)
        for process in removals:
            self.running_processes.remove(process)

    def update_input_queue(self):
        removals = []
        for process in self.processes:
            if process.arrival_time == self.current_time:
                self.input_queue.append(process)
                self.out.add_event(f"Process {process.pid} arrives")
                self.out.add_event(self.get_input_queue())
                removals.append(process)
        for process in removals:
            self.processes.remove(process)

    def get_mmap(self):
        out_mmap = []
        free_frames = self.memory_map.count(None)
        free_chunks = 0
        for i, pid in enumerate(self.memory_map):
            if free_chunks != 0 and pid is not None:
                start = (i - free_chunks) * self.page_size
                end = (free_chunks * self.page_size) - 1 + start
                out_mmap.append(f"{start}-{end}: Free Frame(s)")
                free_frames -= free_chunks
                free_chunks = 0
            if pid is not None:
                out_mmap.append(
                    f"{i*self.page_size}-{(i+1)*self.page_size-1}: {self.mmap_metadata[i]}"
                )
            else:
                free_chunks += 1
        if free_frames > 0:
            out_mmap.append(
                f"{self.total_frames*self.page_size - free_frames*self.page_size}-{self.total_frames*self.page_size-1}: Free Frame(s)"
            )
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
        tmp_input_queue = copy.deepcopy(self.input_queue)
        i = 0
        for process in tmp_input_queue:
            if self.allocate_memory(process):
                process.admission_time = self.current_time
                self.running_processes.append(process)
                self.input_queue.remove(self.input_queue[i])
                self.out.add_event(f"MM moves Process {process.pid} to memory")
                self.out.add_event(self.get_input_queue())
                self.out.add_event("Memory Map: ", self.get_mmap())
            else:
                i += 1

    def allocate_memory(self, process):
        required_frames = (
            process.memory_requirements + self.page_size - 1
        ) // self.page_size
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


class SimulateVSP:
    def __init__(self, processes, memory_size, algorithm):
        self.processes = processes
        self.memory_size = memory_size
        self.algorithm = algorithm

        self.memory_map = [
            {"pid": None, "start": 0, "end": memory_size - 1}
        ]  # Initialize memory as entirely free
        self.current_time = 0
        self.input_queue = []
        self.running_processes = []
        self.finished_processes = []
        self.output_blocks = []
        self.out = None
        self.simulate()

    def simulate(self):
        while (
            self.processes or self.input_queue or self.running_processes
        ) and self.current_time < 100000:
            self.out = OutputBlock(self.current_time)
            self.update_completions()
            self.update_input_queue()
            self.update_queue()
            self.out.output_if_not_empty()
            self.current_time += 1
        top = sum(
            [
                p.admission_time + p.lifetime - p.arrival_time
                for p in self.finished_processes
            ]
        )
        bottom = len(self.finished_processes)
        avg_turnaround_time = top / bottom
        print(format_tat(f"Average Turnaround Time: {avg_turnaround_time:.2f}"))

    def update_completions(self):
        removals = []
        for process in self.running_processes:
            if self.current_time >= process.admission_time + process.lifetime:
                self.free_memory(process.pid)
                self.out.add_event(f"Process {process.pid} completes")
                self.out.add_event("Memory Map: ", self.get_mmap())
                self.finished_processes.append(process)
                removals.append(process)
        for process in removals:
            self.running_processes.remove(process)

    def update_input_queue(self):
        removals = []
        for process in self.processes:
            if process.arrival_time == self.current_time:
                self.input_queue.append(process)
                self.out.add_event(f"Process {process.pid} arrives")
                self.out.add_event(self.get_input_queue())
                removals.append(process)
        for process in removals:
            self.processes.remove(process)

    def get_input_queue(self):
        out = "Input Queue:["
        for process in self.input_queue:
            out += f"{process.pid} "
        if out[-1] == " ":
            out = out[:-1]  # Remove the last space
        out += "]"
        return out

    def free_memory(self, pid):
        # Free memory occupied by the process's segments
        for m in self.memory_map:
            if m["pid"] == pid:
                m["pid"] = None
        self.merge_free_spaces()

    def merge_free_spaces(self):
        # Merges adjacent free spaces in the memory map
        self.sort_memory_map()
        i = 0
        end = len(self.memory_map) - 1
        while i < end:
            if (
                self.memory_map[i]["pid"] is None
                and self.memory_map[i + 1]["pid"] is None
            ):
                self.memory_map[i]["end"] = self.memory_map[i + 1]["end"]
                del self.memory_map[i + 1]
                end -= 1
            else:
                i += 1

    def get_mmap(self):
        out_mmap = []
        self.sort_memory_map()
        for m in self.memory_map:
            if m["pid"] is None:
                out_mmap.append(f"{m['start']}-{m['end']}: Hole")
            else:
                out_mmap.append(f"{m['start']}-{m['end']}: Process {m['pid']}")
        return out_mmap

    def sort_memory_map(self):
        self.memory_map.sort(key=lambda x: x["start"])

    def update_queue(self):
        tmp_input_queue = copy.deepcopy(self.input_queue)
        i = 0
        for process in tmp_input_queue:
            if self.allocate_memory(process):
                process.admission_time = self.current_time
                self.running_processes.append(process)
                self.input_queue.remove(self.input_queue[i])
                self.out.add_event(f"MM moves Process {process.pid} to memory")
                self.out.add_event(self.get_input_queue())
                self.out.add_event("Memory Map: ", self.get_mmap())
            else:
                i += 1

    def allocate_memory(self, process):
        if (
            self.algorithm == 1
        ):  # First-fit, find the first hole that fits the process and allocate it. Then trim the hole and free the extra memory if necessary.
            for m in self.memory_map:
                if (
                    m["pid"] is None
                    and (m["end"] - m["start"]) > process.memory_requirements - 1
                ):
                    hole = {
                        "pid": None,
                        "start": m["start"] + process.memory_requirements,
                        "end": m["end"],
                    }
                    self.memory_map.append(hole)
                    m["pid"] = process.pid
                    m["end"] = m["start"] + process.memory_requirements - 1
                    self.merge_free_spaces()
                    return True
                elif (
                    m["pid"] is None
                    and (m["end"] - m["start"]) == process.memory_requirements - 1
                ):
                    m["pid"] = process.pid
                    return True
            return False
        elif (
            self.algorithm == 2
        ):  # Best-fit, find the smallest hole that fits the process and allocate it. Then trim the hole and free the extra memory if necessary.
            holes = []  # [size, index]
            i = 0
            for m in self.memory_map:
                if (
                    m["pid"] is None
                    and (m["end"] - m["start"]) >= process.memory_requirements - 1
                ):
                    holes.append([(m["end"] - m["start"]), i])
                i += 1
            if holes:
                holes.sort(key=lambda x: x[1])
                holes.sort(key=lambda x: x[0])
                best_hole = self.memory_map[holes[0][1]]
                if (
                    best_hole["end"] - best_hole["start"]
                ) > process.memory_requirements - 1:
                    hole = {
                        "pid": None,
                        "start": best_hole["start"] + process.memory_requirements,
                        "end": best_hole["end"],
                    }
                    self.memory_map.append(hole)
                    self.memory_map[holes[0][1]]["pid"] = process.pid
                    self.memory_map[holes[0][1]]["end"] = (
                        best_hole["start"] + process.memory_requirements - 1
                    )
                    self.merge_free_spaces()
                    return True
                elif (
                    best_hole["end"] - best_hole["start"]
                ) == process.memory_requirements - 1:
                    self.memory_map[holes[0][1]]["pid"] = process.pid
                    return True
            return False
        elif (
            self.algorithm == 3
        ):  # Worst-fit, find the largest hole that fits the process and allocate it. Then trim the hole and free the extra memory if necessary.
            holes = []  # [size, index]
            i = 0
            for m in self.memory_map:
                if (
                    m["pid"] is None
                    and (m["end"] - m["start"]) >= process.memory_requirements - 1
                ):
                    holes.append([(m["end"] - m["start"]), i])
                i += 1
            if holes:
                holes.sort(key=lambda x: x[1])
                holes.sort(key=lambda x: x[0], reverse=True)
                best_hole = self.memory_map[holes[0][1]]
                if (
                    best_hole["end"] - best_hole["start"]
                ) > process.memory_requirements - 1:
                    hole = {
                        "pid": None,
                        "start": best_hole["start"] + process.memory_requirements,
                        "end": best_hole["end"],
                    }
                    self.memory_map.append(hole)
                    self.memory_map[holes[0][1]]["pid"] = process.pid
                    self.memory_map[holes[0][1]]["end"] = (
                        best_hole["start"] + process.memory_requirements - 1
                    )
                    self.merge_free_spaces()
                    return True
                elif (
                    best_hole["end"] - best_hole["start"]
                ) == process.memory_requirements - 1:
                    self.memory_map[holes[0][1]]["pid"] = process.pid
                    return True
            return False


class SimulateSEG:
    def __init__(self, processes, memory_size, algorithm):
        self.processes = processes
        self.memory_size = memory_size
        self.algorithm = algorithm

        self.memory_map = [
            {"pid": None, "start": 0, "end": memory_size - 1, "segment": None}
        ]  # Initialize memory as entirely free
        self.current_time = 0
        self.input_queue = []
        self.running_processes = []
        self.finished_processes = []
        self.output_blocks = []
        self.out = None
        self.simulate()

    def simulate(self):
        while (
            self.processes or self.input_queue or self.running_processes
        ) and self.current_time < 100000:
            self.out = OutputBlock(self.current_time)
            self.update_completions()
            self.update_input_queue()
            self.update_queue()
            self.out.output_if_not_empty()
            self.current_time += 1
        top = sum(
            [
                p.admission_time + p.lifetime - p.arrival_time
                for p in self.finished_processes
            ]
        )
        bottom = len(self.finished_processes)
        avg_turnaround_time = top / bottom
        print(format_tat(f"Average Turnaround Time: {avg_turnaround_time:.2f}"))

    def update_completions(self):
        removals = []
        for process in self.running_processes:
            if self.current_time >= process.admission_time + process.lifetime:
                self.free_memory(process.pid)
                self.out.add_event(f"Process {process.pid} completes")
                self.out.add_event("Memory Map: ", self.get_mmap())
                self.finished_processes.append(process)
                removals.append(process)
        for process in removals:
            self.running_processes.remove(process)

    def update_input_queue(self):
        removals = []
        for process in self.processes:
            if process.arrival_time == self.current_time:
                self.input_queue.append(process)
                self.out.add_event(f"Process {process.pid} arrives")
                self.out.add_event(self.get_input_queue())
                removals.append(process)
        for process in removals:
            self.processes.remove(process)

    def get_input_queue(self):
        out = "Input Queue:["
        for process in self.input_queue:
            out += f"{process.pid} "
        if out[-1] == " ":
            out = out[:-1]  # Remove the last space
        out += "]"
        return out

    def free_memory(self, pid):
        # Free memory occupied by the process's segments
        for m in self.memory_map:
            if m["pid"] == pid:
                m["pid"] = None
                m["segment"] = None
        self.merge_free_spaces()

    def merge_free_spaces(self):
        # Merges adjacent free spaces in the memory map
        self.sort_memory_map()
        i = 0
        end = len(self.memory_map) - 1
        while i < end:
            if (
                self.memory_map[i]["pid"] is None
                and self.memory_map[i + 1]["pid"] is None
            ):
                self.memory_map[i]["end"] = self.memory_map[i + 1]["end"]
                del self.memory_map[i + 1]
                end -= 1
            else:
                i += 1

    def get_mmap(self):
        out_mmap = []
        self.sort_memory_map()
        for m in self.memory_map:
            if m["pid"] is None:
                out_mmap.append(f"{m['start']}-{m['end']}: Hole")
            else:
                out_mmap.append(
                    f"{m['start']}-{m['end']}: Process {m['pid']}, Segment {m['segment']}"
                )
        return out_mmap

    def sort_memory_map(self):
        self.memory_map.sort(key=lambda x: x["start"])

    def update_queue(self):
        tmp_input_queue = copy.deepcopy(self.input_queue)
        i = 0
        for process in tmp_input_queue:
            if self.allocate_memory(process):
                process.admission_time = self.current_time
                self.running_processes.append(process)
                self.input_queue.remove(self.input_queue[i])
                self.out.add_event(f"MM moves Process {process.pid} to memory")
                self.out.add_event(self.get_input_queue())
                self.out.add_event("Memory Map: ", self.get_mmap())
            else:
                i += 1

    def ff_allocate_memory(self, process):
        temp_mmap = copy.deepcopy(self.memory_map)
        segs = process.num_segments
        allocated = 0
        for i in range(segs):  # Allocate each segment
            for m in temp_mmap:
                if (
                    m["pid"] is None
                    and (m["end"] - m["start"]) > process.segments[i] - 1
                ):
                    hole = {
                        "pid": None,
                        "start": m["start"] + process.segments[i],
                        "end": m["end"],
                        "segment": None,
                    }
                    temp_mmap.append(hole)
                    m["pid"] = process.pid
                    m["end"] = m["start"] + process.segments[i] - 1
                    m["segment"] = i
                    allocated += 1
                    break
                elif (
                    m["pid"] is None
                    and (m["end"] - m["start"]) == process.segments[i] - 1
                ):
                    m["pid"] = process.pid
                    m["segment"] = i
                    allocated += 1
                    break
        if allocated == segs:
            self.memory_map = temp_mmap
            self.merge_free_spaces()
            return True
        else:
            return False

    def bf_allocate_memory(self, process):
        temp_mmap = copy.deepcopy(self.memory_map)
        segs = process.num_segments
        allocated = 0
        for j in range(segs):  # Allocate each segment
            holes = []  # [size, index]
            i = 0
            for m in temp_mmap:
                if (
                    m["pid"] is None
                    and (m["end"] - m["start"]) >= process.segments[j] - 1
                ):
                    holes.append([(m["end"] - m["start"]), i])
                i += 1
            if holes:
                holes.sort(key=lambda x: x[1])
                holes.sort(key=lambda x: x[0])
                best_hole = temp_mmap[holes[0][1]]
                if (best_hole["end"] - best_hole["start"]) > process.segments[j] - 1:
                    hole = {
                        "pid": None,
                        "start": best_hole["start"] + process.segments[j],
                        "end": best_hole["end"],
                        "segment": None,
                    }
                    temp_mmap.append(hole)
                    temp_mmap[holes[0][1]]["pid"] = process.pid
                    temp_mmap[holes[0][1]]["end"] = (
                        best_hole["start"] + process.segments[j] - 1
                    )
                    temp_mmap[holes[0][1]]["segment"] = j
                    allocated += 1
                elif (best_hole["end"] - best_hole["start"]) == process.segments[j] - 1:
                    temp_mmap[holes[0][1]]["pid"] = process.pid
                    temp_mmap[holes[0][1]]["segment"] = j
                    allocated += 1
        if allocated == segs:
            self.memory_map = temp_mmap
            self.merge_free_spaces()
            return True
        else:
            return False

    def wf_allocate_memory(self, process):
        temp_mmap = copy.deepcopy(self.memory_map)
        segs = process.num_segments
        allocated = 0
        for j in range(segs):  # Allocate each segment
            holes = []  # [size, index]
            i = 0
            for m in temp_mmap:
                if (
                    m["pid"] is None
                    and (m["end"] - m["start"]) >= process.segments[j] - 1
                ):
                    holes.append([(m["end"] - m["start"]), i])
                i += 1
            if holes:
                holes.sort(key=lambda x: x[1])
                holes.sort(key=lambda x: x[0], reverse=True)
                best_hole = temp_mmap[holes[0][1]]
                if (best_hole["end"] - best_hole["start"]) > process.segments[j] - 1:
                    hole = {
                        "pid": None,
                        "start": best_hole["start"] + process.segments[j],
                        "end": best_hole["end"],
                        "segment": None,
                    }
                    temp_mmap.append(hole)
                    temp_mmap[holes[0][1]]["pid"] = process.pid
                    temp_mmap[holes[0][1]]["end"] = (
                        best_hole["start"] + process.segments[j] - 1
                    )
                    temp_mmap[holes[0][1]]["segment"] = j
                    allocated += 1
                elif (best_hole["end"] - best_hole["start"]) == process.segments[j] - 1:
                    temp_mmap[holes[0][1]]["pid"] = process.pid
                    temp_mmap[holes[0][1]]["segment"] = j
                    allocated += 1
        if allocated == segs:
            self.merge_free_spaces()
            self.memory_map = temp_mmap
            return True
        else:
            return False

    def allocate_memory(self, process):
        if self.algorithm == 1:  # First-fit
            return self.ff_allocate_memory(process)
        elif self.algorithm == 2:  # Best-fit
            return self.bf_allocate_memory(process)
        elif self.algorithm == 3:  # Worst-fit
            return self.wf_allocate_memory(process)


def read_workload_file(filename):
    processes = []
    with open(filename, "r") as file:
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
        algorithm = int(
            input("Fit algorithm (1 - first-fit, 2 - best-fit, 3 - worst-fit): ")
        )
        page_size = None
    else:
        page_size = int(input("Page/Frame size: "))
        algorithm = None
    filename = input("Enter the name of the workload file: ")
    return memory_size, policy, algorithm, page_size, filename


def main():
    memory_size, policy, algorithm, page_size, filename = get_config()
    processes = read_workload_file(filename)
    if policy == 1:
        SimulateVSP(processes, memory_size, algorithm)
    elif policy == 2:
        SimulatePAG(processes, memory_size, page_size)
    elif policy == 3:
        SimulateSEG(processes, memory_size, algorithm)


if __name__ == "__main__":
    main()
