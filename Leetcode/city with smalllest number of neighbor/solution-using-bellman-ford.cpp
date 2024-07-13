#include <iostream>
#include <vector>
#include <limits.h>

using namespace std;

class Solution {
public:
    vector<int> bellmanFord(int n, int start, vector<vector<int>>& edges, int distanceThreshold) {
        vector<int> distances(n, INT_MAX);
        distances[start] = 0;

        // Relax all edges n-1 times
        for (int i = 1; i < n; ++i) {
            for (const auto& edge : edges) {
                int u = edge[0];
                int v = edge[1];
                int weight = edge[2];
                if (distances[u] != INT_MAX && distances[u] + weight < distances[v]) {
                    distances[v] = distances[u] + weight;
                }
                if (distances[v] != INT_MAX && distances[v] + weight < distances[u]) {
                    distances[u] = distances[v] + weight;
                }
            }
        }

        return distances;
    }

    int findTheCity(int n, vector<vector<int>>& edges, int distanceThreshold) {
        int minReachableCount = INT_MAX;
        int resultCity = -1;

        for (int i = 0; i < n; ++i) {
            vector<int> distances = bellmanFord(n, i, edges, distanceThreshold);
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
    cout << "The city with the smallest number of neighbors at a threshold distance is: " << result << endl;
    return 0;
}
