#!/bin/bash

(cd ./server && gnome-terminal --title="server" -- bash -c "./server WIBreast; exec bash")

gnome-terminal --title="client1" -- bash -c "./app ./dataset/WIBreastData/breast_cancer_train_part_1.txt WIBreast; exec bash"

gnome-terminal --title="client2" -- bash -c "./app ./dataset/WIBreastData/breast_cancer_train_part_2.txt WIBreast; exec bash"

gnome-terminal --title="client3" -- bash -c "./app ./dataset/WIBreastData/breast_cancer_train_part_3.txt WIBreast; exec bash"
