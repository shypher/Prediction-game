import React from "react"
type inputProps = {
    value: string
    handleChange:(event: React.ChangeEvent<HTMLInputElement>)=> void
}

export const Input = ({value, handleChange}: inputProps) =>{
    const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>)=>{
        console.log(event)
    }
    return <input type ='text' value = {value} onChange={handleChange}/>
}