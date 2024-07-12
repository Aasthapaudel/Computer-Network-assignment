
def find_cheapest_price(n, flights, src, dst, k):
   prices = [float("inf")]*n
   prices[src] = 0

   for i in range(k+1):
      tmpPrices = prices.copy()

      for s,d,p in flights:
         if prices[s] != float("inf") and prices[s]+p <tmpPrices[d]:
            tmpPrices[d] = prices[s]+p

      prices = tmpPrices
    
   if prices[dst] == float("inf"):
      return -1
   else:
      return prices[dst]
   
n = 4
flights = [[0, 1, 100], [1, 2, 100], [2, 3, 100], [0, 2, 500]]
src = 0
dst = 3
K = 1
print(find_cheapest_price(n, flights, src, dst, K))
