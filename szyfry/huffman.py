from heapq import heappush, heappop
from collections import defaultdict, Counter

class Node:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other):
        return self.freq < other.freq

class HuffmanCoding:
    def __init__(self):
        self.codes = {}
        self.reverse_mapping = {}

    def build_frequency_table(self, text):
        return Counter(text)

    def build_heap(self, frequency):
        heap = []
        for char, freq in frequency.items():
            heappush(heap, Node(char, freq))
        return heap

    def merge_nodes(self, heap):
        while len(heap) > 1:
            left = heappop(heap)
            right = heappop(heap)
            merged = Node(None, left.freq + right.freq)
            merged.left = left
            merged.right = right
            heappush(heap, merged)
        return heap[0]

    def build_codes(self, root, current_code=""):
        if root is None:
            return

        if root.char is not None:
            self.codes[root.char] = current_code
            self.reverse_mapping[current_code] = root.char
            return

        self.build_codes(root.left, current_code + "0")
        self.build_codes(root.right, current_code + "1")

    def encode(self, text):
        frequency = self.build_frequency_table(text)
        heap = self.build_heap(frequency)
        root = self.merge_nodes(heap)
        self.build_codes(root)

        encoded_text = ''.join(self.codes[char] for char in text)
        return encoded_text

    def decode(self, encoded_text):
        current_code = ""
        decoded_text = ""

        for bit in encoded_text:
            current_code += bit
            if current_code in self.reverse_mapping:
                decoded_text += self.reverse_mapping[current_code]
                current_code = ""
        return decoded_text



