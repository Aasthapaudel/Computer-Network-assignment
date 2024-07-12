import heapq
import collections

def network_delay_time(times, N, K):
    # Create the graph
    edges = collections.defaultdict(list)
    for u, v, w in times:
        edges[u].append((v, w))
    
    min_heap = [(0, K)]
    visit = {}

    while min_heap:
        time, node = heapq.heappop(min_heap)
        
        if node in visit:
            continue

        visit[node] = time

        for neighbor, weight in edges[node]:
            if neighbor not in visit:
                heapq.heappush(min_heap, (time + weight, neighbor))

    if len(visit) == N:
        return max(visit.values())
    else:
        return -1

times = [[2, 1, 1], [2, 3, 1], [3, 4, 1]]
N = 4
K = 2
print(network_delay_time(times, N, K)) 
