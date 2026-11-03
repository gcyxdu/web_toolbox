from graphviz import Source
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

# Define the DOT code for the decision tree
# 定义决策树的DOT代码
dataset_paths = {
    "wine": "../UCI_dectrees/wine",
    "iris": "../UCI_dectrees/iris",
    "breast": "../UCI_dectrees/breast",
    "digits": "../UCI_dectrees/digits",
    "diabetes": "../UCI_dectrees/diabetes",
    "linnerud": "../UCI_dectrees/linnerud",
    "boston": "../UCI_dectrees/boston"
}

with open('digits', 'r') as f:
    dot_code = f.read()

# Use Graphviz's Source to generate the image
# 使用Graphviz的Source生成图像
src = Source(dot_code)

# Save the image in PNG format
# 以PNG格式保存图像
src.render("digits", format="png")

# Display the image using matplotlib
# 使用matplotlib显示图像
img = mpimg.imread("digits.png")
plt.figure(figsize=(10, 10))  # Set the image size
# 设置图像大小
plt.imshow(img)
plt.axis('off')  # Hide the axes
# 隐藏坐标轴
plt.show()
