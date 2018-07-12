<?php

class Route
{
    private $db;

    public function __construct()
    {
        $this->db = new Database;
    }

    public function add($data)
    {
        $this->db->query(
            "insert into routes (departure, destination, fare) values (:from, :to, :fare)"
        );
        $this->db->bind(':from', $data['from']);
        $this->db->bind(':to', $data['to']);
        $this->db->bind(':fare', $data['fare']);
        if ($this->db->execute()) {
            return true;
        } else {
            return false;
        }
    }

    public function all()
    {
        $this->db->query("select * from routes");
        $rows = $this->db->resultSet();
        if ($this->db->rowCount() >0) {
            return $rows;
        } else {
            return false;
        }
    }
}
