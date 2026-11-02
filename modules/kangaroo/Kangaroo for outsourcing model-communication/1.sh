# Get the directory where the script is located
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Set the build directory
BUILD_DIR="$SCRIPT_DIR/build"

# Clean up the old build directory
echo "Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Run CMake
echo "Configuring project with CMake..."
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR"

# Compile the project
echo "Building project..."
cmake --build "$BUILD_DIR"

cd build

for i in $( seq 0 6 )
do
    # Execute ./examples and pass the current loop value
    ./examples "$i"
	./nonexamples "$i"
done

cd ..