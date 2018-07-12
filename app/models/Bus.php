<?php

class Bus
{
    private $db;

    public function __construct()
    {
        $this->db = new Database;
    }

    public function findBusByRegPlate($regPlate)
    {
        $this->db->query("select * from buses where regPlate = :regPlate");
        $this->db->bind(':regPlate', $regPlate);
        $row = $this->db->single();

        // Check row
        if ($this->db->rowCount() > 0) {
            return true;
        } else {
            return false;
        }
    }

    // public function add($bus)
    // {
    //     $this->db->query(
    //         "insert into buses (regPlate, capacity, route_id) values (:regPlate, :capacity, :route_id)"
    //     );
    //     $this->db->bind(':regPlate', $bus['regPlate']);
    //     $this->db->bind(':capacity', $bus['capacity']);
    //     $this->db->bind(':route_id', $bus['busRouteID']);
    //     if ($this->db->execute()) {
    //         return true;
    //     } else {
    //         return false;
    //     }
    // }

    public function findBusRouteID($from, $to)
    {
        $this->db->query('select * from routes where from=:from and to=:to');
        $this->db->bind(':from', $from);
        $this->db->bind(':to', $to);

        $row = $this->db->single();

        // Check row
        if ($this->db->rowCount() > 0) {
            return $row;
        } else {
            return false;
        }
    }
}
