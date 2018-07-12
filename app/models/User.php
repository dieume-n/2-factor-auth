<?php

class User
{
    private $db;

    public function __construct()
    {
        $this->db = new Database;
    }

    public function findUserByEmail($email)
    {
        $this->db->query("select * from users where email = :email");
        $this->db->bind(':email', $email);
        $row = $this->db->single();

        // Check row
        if ($this->db->rowCount() > 0) {
            return true;
        } else {
            return false;
        }
    }

    public function findUserByTelephone($telephone)
    {
        $this->db->query("select * from users where telephone = :telephone");
        $this->db->bind(':telephone', $telephone);
        $row = $this->db->single();

        // Check row
        if ($this->db->rowCount() > 0) {
            return true;
        } else {
            return false;
        }
    }

    public function findUserByID($id)
    {
        $this->db->query("select * from users where id = :id");
        $this->db->bind(':id', $id);
        $row = $this->db->single();

        // Check row
        if ($this->db->rowCount() > 0) {
            return $row;
        } else {
            return false;
        }
    }

    public function register($data)
    {
        $this->db->query(
            "insert into users (name, email, password) 
                values (:name, :email, :password)"
        );
        $this->db->bind(':name', $data['name']);
        $this->db->bind(':email', $data['email']);
        $this->db->bind(':password', $data['password']);
        if ($this->db->execute()) {
            return true;
        } else {
            return false;
        }
    }

    

    public function login($email, $password)
    {
        $this->db->query('select * from users where email=:email');
        $this->db->bind(':email', $email);

        $row = $this->db->single();
        $hashedPassword = $row->password;
        if (password_verify($password, $hashedPassword)) {
            return $row;
        } else {
            return false;
        }
    }

    public function allUsers()
    {
        $this->db->query(
            "select * from users"
        );
        
        $rows = $this->db->resultSet();
        if ($this->db->rowCount() >0) {
            return $rows;
        } else {
            return false;
        }
    }
}
