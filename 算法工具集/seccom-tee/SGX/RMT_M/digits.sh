#!/bin/bash

(cd ./server && gnome-terminal --title="server" -- bash -c "./server digits 4 2 0.1; exec bash")

gnome-terminal --title="client1" -- bash -c "./app ./dataset/digitsData/digits_train_part_1.txt digits; exec bash"

gnome-terminal --title="client2" -- bash -c "./app ./dataset/digitsData/digits_train_part_2.txt digits; exec bash"

gnome-terminal --title="client3" -- bash -c "./app ./dataset/digitsData/digits_train_part_3.txt digits; exec bash"
