import os
CHUNK_SIZE = 16
def generate_p4_defines(filename="chunksize.p4h"):
    path = os.path.join("p4", filename)
    with open(path, "w") as f:
        f.write(f"#define CHUNK_SIZE {CHUNK_SIZE}")

if __name__ == "__main__":
    generate_p4_defines()