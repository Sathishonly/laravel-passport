<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Jenssegers\Mongodb\Eloquent\Model;

class forgotpassword extends Model
{
    use HasFactory;
    protected $connection = 'mongodb';
    protected $collection = 'forgotpassword';

    protected $fillable = ['email', 'otp'];
}
