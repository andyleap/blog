package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/jmoiron/sqlx"
)

type AutoMigrate struct {
	Tables map[string]interface{}
}

func (a *AutoMigrate) AddTable(name string, table interface{}) {
	a.Tables[name] = table
}

func (a *AutoMigrate) Migrate(db *sqlx.DB) error {
	for name, table := range a.Tables {
		if err := a.removeRefConstraints(db, name, table); err != nil {
			return fmt.Errorf("error removing ref constraints for %s: %s", name, err)
		}
	}
	for name, table := range a.Tables {
		if err := a.migrateTable(db, name, table); err != nil {
			return fmt.Errorf("error migrating %s: %s", name, err)
		}
	}
	for name, table := range a.Tables {
		if err := a.addRefConstraints(db, name, table); err != nil {
			return fmt.Errorf("error adding ref constraints for %s: %s", name, err)
		}
	}
	return nil
}

type colinfo struct {
	typ      string
	rel      string
	identity bool
}

func (a *AutoMigrate) migrateTable(db *sqlx.DB, name string, table interface{}) error {
	rows, err := db.Query(`SELECT
		column_name,
		data_type,
		is_identity
	 FROM
		information_schema.columns
	 WHERE
		table_name = $1`, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	existing := map[string]colinfo{}
	for rows.Next() {
		var columnName, dataType, isIdentity string
		if err := rows.Scan(&columnName, &dataType, &isIdentity); err != nil {
			return err
		}
		existing[columnName] = colinfo{
			typ:      dataType,
			identity: isIdentity == "YES",
		}
	}
	desired := map[string]colinfo{}
	rv := reflect.ValueOf(table).Type()
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		columnName := field.Name
		if tag := field.Tag.Get("db"); tag != "" {
			columnName = tag
		}
		dataType := ""
		ci := colinfo{
			identity: field.Tag.Get("identity") == "true",
		}
		switch field.Type.Kind() {
		case reflect.Int:
			dataType = "integer"
		case reflect.String:
			dataType = "text"
		case reflect.Slice:
			if field.Type.Elem().Kind() == reflect.Uint8 {
				dataType = "text"
				break
			}
			fallthrough
		default:
			return fmt.Errorf("unsupported type %s", field.Type.Kind())
		}
		ci.typ = dataType
		desired[columnName] = ci
	}

	if len(existing) == 0 {
		cols := []string{}
		for columnName, ci := range desired {
			col := fmt.Sprintf("%s %s", columnName, ci.typ)
			if ci.identity {
				col += " GENERATED ALWAYS AS IDENTITY"
			}
			cols = append(cols, col)
		}
		create := fmt.Sprintf("CREATE TABLE %s (", name) + strings.Join(cols, ", ") + ")"
		_, err := db.Exec(create)
		if err != nil {
			return err
		}
	} else {
		actions := []string{}
		for columnName, ci := range desired {
			if _, ok := existing[columnName]; !ok {
				action := fmt.Sprintf("ADD COLUMN %s %s", columnName, ci.typ)
				if ci.identity {
					action += " GENERATED ALWAYS AS IDENTITY"
				}
				actions = append(actions, action)
				continue
			}
			e := existing[columnName]
			if e.typ != ci.typ {
				actions = append(actions, fmt.Sprintf("ALTER COLUMN %s TYPE %s", columnName, ci.typ))
			}
			if e.identity != ci.identity {
				if ci.identity {
					actions = append(actions, fmt.Sprintf("ALTER COLUMN %s ADD GENERATED ALWAYS AS IDENTITY", columnName))
				} else {
					actions = append(actions, fmt.Sprintf("ALTER COLUMN %s DROP IDENTITY", columnName))
				}
			}
		}
		for columnName, _ := range existing {
			if _, ok := desired[columnName]; !ok {
				actions = append(actions, fmt.Sprintf("DROP COLUMN %s", columnName))
			}
		}
		if len(actions) > 0 {
			alter := fmt.Sprintf("ALTER TABLE %s ", name) + strings.Join(actions, ", ")
			_, err := db.Exec(alter)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type refinfo struct {
	col      string
	refTable string
	refCol   string
}

var refConstraintQuery = `
select
	conname,
	att2.attname as "col", 
	cl.relname as "ref_table", 
	att.attname as "ref_col"
from
   (select 
        unnest(con1.conkey) as "parent", 
        unnest(con1.confkey) as "child", 
        con1.confrelid, 
        con1.conrelid,
        con1.conname
    from 
        pg_class cl
        join pg_namespace ns on cl.relnamespace = ns.oid
        join pg_constraint con1 on con1.conrelid = cl.oid
    where
        cl.relname = $1
        and ns.nspname = 'public'
        and con1.contype = 'f'
   ) con
   join pg_attribute att on
       att.attrelid = con.confrelid and att.attnum = con.child
   join pg_class cl on
       cl.oid = con.confrelid
   join pg_attribute att2 on
       att2.attrelid = con.conrelid and att2.attnum = con.parent
`

// removeRefConstraints removes foreign key constraints from the table that don't exist in the struct
func (a *AutoMigrate) removeRefConstraints(db *sqlx.DB, name string, table interface{}) error {
	rows, err := db.Query(refConstraintQuery, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	constraints := map[refinfo]string{}
	for rows.Next() {
		var constraintName, columnName, referencedTableName, referencedColumnName string
		if err := rows.Scan(&constraintName, &columnName, &referencedTableName, &referencedColumnName); err != nil {
			return err
		}
		ri := refinfo{
			col:      columnName,
			refTable: referencedTableName,
			refCol:   referencedColumnName,
		}
		constraints[ri] = fmt.Sprintf("DROP CONSTRAINT %s", constraintName)
	}
	rv := reflect.ValueOf(table).Type()
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		columnName := field.Name
		if tag := field.Tag.Get("db"); tag != "" {
			columnName = tag
		}
		if tag := field.Tag.Get("relation"); tag != "" {
			parts := strings.Split(tag, ".")
			if len(parts) != 2 {
				return fmt.Errorf("invalid relation tag %s", tag)
			}
			ri := refinfo{
				col:      columnName,
				refTable: parts[0],
				refCol:   parts[1],
			}
			delete(constraints, ri)
		}
	}
	actions := []string{}
	for _, drop := range constraints {
		actions = append(actions, drop)
	}
	if len(actions) > 0 {
		alter := fmt.Sprintf("ALTER TABLE %s ", name) + strings.Join(actions, ", ")
		_, err := db.Exec(alter)
		if err != nil {
			return err
		}
	}
	return nil
}

// addRefConstraints adds foreign key constraints to the table that exist in the struct, but not in the database
func (a *AutoMigrate) addRefConstraints(db *sqlx.DB, name string, table interface{}) error {

	constraints := map[refinfo]struct{}{}
	rv := reflect.ValueOf(table).Type()
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		columnName := field.Name
		if tag := field.Tag.Get("db"); tag != "" {
			columnName = tag
		}
		if tag := field.Tag.Get("relation"); tag != "" {
			parts := strings.Split(tag, ".")
			if len(parts) != 2 {
				return fmt.Errorf("invalid relation tag %s", tag)
			}
			ri := refinfo{
				col:      columnName,
				refTable: parts[0],
				refCol:   parts[1],
			}
			constraints[ri] = struct{}{}
		}
	}
	rows, err := db.Query(refConstraintQuery, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var constraintName, columnName, referencedTableName, referencedColumnName string
		if err := rows.Scan(&constraintName, &columnName, &referencedTableName, &referencedColumnName); err != nil {
			return err
		}
		ri := refinfo{
			col:      columnName,
			refTable: referencedTableName,
			refCol:   referencedColumnName,
		}
		delete(constraints, ri)
	}

	actions := []string{}
	for ri := range constraints {
		actions = append(actions, fmt.Sprintf("ADD FOREIGN KEY (%s) REFERENCES %s (%s)", ri.col, ri.refTable, ri.refCol))
	}
	if len(actions) > 0 {
		alter := fmt.Sprintf("ALTER TABLE %s ", name) + strings.Join(actions, ", ")
		_, err := db.Exec(alter)
		if err != nil {
			return err
		}
	}
	return nil
}
