#!/bin/bash

(cd ./server && gnome-terminal --title="server" -- bash -c "./server stroke; exec bash")

gnome-terminal --title="client1" -- bash -c "./app ./dataset/strokeData/stroke_train_part_1.txt stroke; exec bash"

gnome-terminal --title="client2" -- bash -c "./app ./dataset/strokeData/stroke_train_part_2.txt stroke; exec bash"

gnome-terminal --title="client3" -- bash -c "./app ./dataset/strokeData/stroke_train_part_3.txt stroke; exec bash"
