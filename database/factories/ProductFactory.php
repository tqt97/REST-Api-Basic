<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

class ProductFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        $name = $this->faker->name();
        $slug = Str::slug($name, '-');
        return [
            'name' => $name,
            'description' => $this->faker->sentence(),
            'price' => $this->faker->randomFloat(100, 0, 1000),
            'slug' =>  $slug
        ];
    }
}
