<?php

function redirect($location)
{
    if ($location == '/') {
        header('Location:' . URLROOT);
    } else {
        header('Location:' . URLROOT. '/' . $location);
    }
}
