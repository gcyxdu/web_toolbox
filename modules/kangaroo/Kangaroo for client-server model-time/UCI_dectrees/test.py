from graphviz import Source
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

# Define the DOT code for a decision tree
dataset_paths = {
    "wine": "../UCI_dectrees/wine",
    "iris": "../UCI_dectrees/iris",
    "breast": "../UCI_dectrees/breast",
    "digits": "../UCI_dectrees/digits",
    "diabetes": "../UCI_dectrees/diabetes",
    "linnerud": "../UCI_dectrees/linnerud",
    "boston": "../UCI_dectrees/boston"
}

with open('iris', 'r') as f:
    dot_code = f.read()

# Generate an image using Graphviz's Source
src = Source(dot_code)

# Save the image in PNG format
src.render("decision_tree", format="png")

# Display the image using matplotlib
img = mpimg.imread("decision_tree.png")
plt.figure(figsize=(10, 10))  # Set the image size
plt.imshow(img)
plt.axis('off')  # Hide the axes
plt.show()
