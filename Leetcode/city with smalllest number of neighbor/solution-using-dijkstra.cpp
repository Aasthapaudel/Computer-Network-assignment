#include <iostream>
#include <vector>
#include <queue>
#include <limits.h>
#include <algorithm>

using namespace std;

typedef pair<int, int> pii;

class Solution {
public:
    vector<vector<pii>> graph;

    vector<int> dijkstra(int n, int start, int distanceThreshold) {
        vector<int> distances(n, INT_MAX);
        distances[start] = 0;
        priority_queue<pii, vector<pii>, greater<pii>> pq;
        pq.push({0, start});

        while (!pq.empty()) {
            int u = pq.top().second;
            int dist = pq.top().first;
            pq.pop();

            if (dist > distances[u]) continue;

            for (const auto& edge : graph[u]) {
                int v = edge.first;
                int weight = edge.second;

                if (distances[u] + weight < distances[v]) {
                    distances[v] = distances[u] + weight;
                    pq.push({distances[v], v});
                }
            }
        }

        return distances;
    }

    int findTheCity(int n, vector<vector<int>>& edges, int distanceThreshold) {
        graph = vector<vector<pii>>(n);

        for (const auto& edge : edges) {
            int u = edge[0];
            int v = edge[1];
            int weight = edge[2];
            graph[u].emplace_back(v, weight);
            graph[v].emplace_back(u, weight);
        }

        int minReachableCount = INT_MAX;
        int resultCity = -1;

        for (int i = 0; i < n; ++i) {
            vector<int> distances = dijkstra(n, i, distanceThreshold);
            int reachableCount = 0;

            for (int j = 0; j < n; ++j) {
                if (i != j && distances[j] <= distanceThreshold) {
                    reachableCount++;
                }
            }

            if (reachableCount < minReachableCount || (reachableCount == minReachableCount && i > resultCity)) {
                minReachableCount = reachableCount;
                resultCity = i;
            }
        }

        return resultCity;
    }
};
int main() {
    Solution sol;
    int n = 4;
    vector<vector<int>> edges = {{0, 1, 3}, {1, 2, 1}, {1, 3, 4}, {2, 3, 1}};
    int distanceThreshold = 4;

    int result = sol.findTheCity(n, edges, distanceThreshold);
    cout << "Output: " << result << endl;

    return 0;
}

